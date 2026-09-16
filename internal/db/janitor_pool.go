package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	janitorSchema     = "janitor"
	janitorSearchPath = "pg_catalog, janitor, pg_temp"
)

// OpenJanitorPool gives Janitor's connections one explicit private application schema while
// resolving PostgreSQL built-ins before any role-owned object. All Janitor writes are schema
// qualified, so catalog-first lookup removes a shadowing surface without changing ownership.
func OpenJanitorPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse janitor database URL")
	}
	// Do not allow a connection-string `options` parameter to issue a later SET and
	// redirect unqualified maintenance queries into another schema. Janitor has no
	// need for arbitrary startup options; its private search path is fixed here.
	delete(poolConfig.ConnConfig.RuntimeParams, "options")
	poolConfig.ConnConfig.RuntimeParams["search_path"] = janitorSearchPath
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("open janitor database pool")
	}
	return pool, nil
}
