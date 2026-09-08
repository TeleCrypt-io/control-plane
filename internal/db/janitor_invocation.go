package db

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrJanitorAlreadyRunning means another one-shot Janitor currently owns the database-wide
// invocation lease. The lease is session-scoped, so the dedicated acquired connection must stay
// checked out until the whole invocation finishes.
var ErrJanitorAlreadyRunning = errors.New("janitor invocation already running")

const janitorInvocationLockID int64 = 0x54454c5357454550 // "TELSWEEP"

const advisoryLockCleanupTimeout = 2 * time.Second

// JanitorInvocationLock is a database-wide single-flight lease for one Janitor process.
type JanitorInvocationLock struct {
	conn       *pgxpool.Conn
	once       sync.Once
	releaseErr error
}

// AcquireJanitorInvocationLock takes a non-blocking, session-scoped advisory lock. A caller that
// loses the race must exit before migration or any external MAS/SMTP action.
func AcquireJanitorInvocationLock(ctx context.Context, pool *pgxpool.Pool) (*JanitorInvocationLock, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire janitor invocation connection: %w", err)
	}
	var acquired bool
	if err := conn.QueryRow(ctx, `SELECT pg_catalog.pg_try_advisory_lock($1)`, janitorInvocationLockID).Scan(&acquired); err != nil {
		acquireErr := fmt.Errorf("acquire janitor invocation lock: %w", err)
		if closeErr := discardPoolConn(conn); closeErr != nil {
			return nil, errors.Join(acquireErr, fmt.Errorf("close discarded janitor invocation connection: %w", closeErr))
		}
		return nil, acquireErr
	}
	if !acquired {
		conn.Release()
		return nil, ErrJanitorAlreadyRunning
	}
	return &JanitorInvocationLock{conn: conn}, nil
}

// Release gives back the advisory lease and returns the dedicated connection to the pool. It is
// safe to call it again from cleanup code; the first result is retained. Unlock and discarded-
// connection close failures are returned together. The invocation context is the one-shot's hard
// budget; if it has expired, the connection is discarded rather than attempting an unbounded
// unlock on an already-failed invocation.
func (l *JanitorInvocationLock) Release(ctx context.Context) error {
	if l == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	l.once.Do(func() {
		l.releaseErr = releaseJanitorInvocationLock(l.conn, janitorInvocationLockID, ctx)
		l.conn = nil
	})
	return l.releaseErr
}

func releaseJanitorInvocationLock(conn *pgxpool.Conn, lockID int64, ctx context.Context) error {
	return releaseAdvisoryLockWithContext(conn, lockID, ctx)
}

// releaseAdvisoryLock is the migration cleanup adapter. All advisory-lock cleanup uses the same
// bounded policy, whether the caller has the invocation context or is running from a defer that
// predates it.
func releaseAdvisoryLock(conn *pgxpool.Conn, lockID int64) error {
	return releaseAdvisoryLockWithContext(conn, lockID, context.Background())
}

func releaseAdvisoryLockWithContext(conn *pgxpool.Conn, lockID int64, parent context.Context) error {
	ctx, cancel := boundedCleanupContext(parent)
	defer cancel()
	var unlocked bool
	unlockErr := conn.QueryRow(ctx, `SELECT pg_catalog.pg_advisory_unlock($1)`, lockID).Scan(&unlocked)
	if unlockErr != nil || !unlocked {
		var releaseErr error
		if unlockErr != nil {
			releaseErr = fmt.Errorf("release advisory lock: %w", unlockErr)
		} else {
			releaseErr = errors.New("release advisory lock: database did not confirm unlock")
		}
		if closeErr := discardPoolConn(conn); closeErr != nil {
			return errors.Join(releaseErr, fmt.Errorf("close discarded advisory-lock connection: %w", closeErr))
		}
		return releaseErr
	}
	conn.Release()
	return nil
}

func boundedCleanupContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, advisoryLockCleanupTimeout)
}

// discardPoolConn takes the connection out of the pool and closes it, so no uncertain session
// state can be reused. Closing is bounded; a connection that does not close in time is still no
// longer owned by the pool.
func discardPoolConn(conn *pgxpool.Conn) error {
	pgConn := conn.Hijack()
	ctx, cancel := boundedCleanupContext(context.Background())
	defer cancel()
	return pgConn.Close(ctx)
}
