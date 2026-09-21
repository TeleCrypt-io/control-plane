package janitor

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"sync"
)

// SMTPMailer sends the operator report as plain text over a TLS-required SMTP connection.
// It negotiates STARTTLS explicitly and fails closed if the server does not advertise STARTTLS
// or if the TLS handshake fails — it never authenticates or sends in plaintext. Authentication
// uses smtp.PlainAuth only after a successful STARTTLS upgrade. SMTP operations are canceled when
// the request context ends. Certificate verification
// requires a working CA trust store in the runtime environment — see the Dockerfile's
// ca-certificates note (scratch has none by default).
type SMTPMailer struct {
	Host, Port, Username, Password, From string
	// tlsConfig, when non-nil, overrides the default TLS config used for STARTTLS.
	// Production code leaves this nil; tests use it to skip certificate verification
	// for self-signed test certificates.
	tlsConfig *tls.Config
}

func (m *SMTPMailer) Send(ctx context.Context, to, subject, body string) (resultErr error) {
	if err := validateSMTPMessage(m.From, to, subject, body); err != nil {
		return err
	}
	addr := net.JoinHostPort(m.Host, m.Port)
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp dial %s: %w", addr, err)
	}
	managedConn := &smtpConnection{Conn: conn}
	finishContextClose := startSMTPContextClose(ctx, managedConn)
	defer func() {
		resultErr = errors.Join(resultErr, finishContextClose())
	}()

	client, err := smtp.NewClient(managedConn, m.Host)
	if err != nil {
		return errors.Join(fmt.Errorf("smtp new client: %w", err), closeSMTPConnection(managedConn))
	}
	clientClosed := false
	defer func() {
		if !clientClosed {
			if closeErr := client.Close(); closeErr != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("smtp close client: %w", closeErr))
			}
		}
	}()

	if err := client.Hello("telecrypt.io"); err != nil {
		return fmt.Errorf("smtp hello: %w", err)
	}

	if ok, _ := client.Extension("STARTTLS"); !ok {
		return errors.New("smtp: server does not advertise STARTTLS — refusing to send in plaintext")
	}

	tlsCfg := m.tlsConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{ServerName: m.Host}
	}
	if err := client.StartTLS(tlsCfg); err != nil {
		return fmt.Errorf("smtp starttls: %w", err)
	}

	auth := smtp.PlainAuth("", m.Username, m.Password, m.Host)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}

	if err := client.Mail(m.From); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt to: %w", err)
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", m.From, to, subject, body)
	if _, err := wc.Write([]byte(msg)); err != nil {
		return fmt.Errorf("smtp write body: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp close body: %w", err)
	}

	quitErr := client.Quit()
	if quitErr == nil {
		clientClosed = true
	}
	return quitErr
}

func closeSMTPConnection(conn net.Conn) error {
	if closeErr := conn.Close(); closeErr != nil {
		return fmt.Errorf("smtp close connection: %w", closeErr)
	}
	return nil
}

// smtpConnection makes the raw connection's close operation one-owner and idempotent. The
// cancellation callback and smtp.Client both need a close boundary, but only the first caller
// may close the underlying socket; the first close result remains visible to that caller.
type smtpConnection struct {
	net.Conn
	closeOnce sync.Once
	closeErr  error
}

func (c *smtpConnection) Close() error {
	first := false
	c.closeOnce.Do(func() {
		first = true
		c.closeErr = c.Conn.Close()
	})
	if !first {
		return nil
	}
	return c.closeErr
}

// startSMTPContextClose arranges for context cancellation to unblock the SMTP operation and
// returns a wait function that stops or observes the callback before Send returns. The managed
// connection owns repeated-close handling; this callback's close result remains visible.
func startSMTPContextClose(ctx context.Context, conn net.Conn) func() error {
	result := make(chan error, 1)
	stop := context.AfterFunc(ctx, func() {
		result <- closeSMTPConnection(conn)
	})
	return func() error {
		if stop() {
			return nil
		}
		return <-result
	}
}

func validateSMTPMessage(from, to, subject, body string) error {
	if from == "" || to == "" || subject == "" {
		return errors.New("smtp: message headers must be non-empty")
	}
	if strings.ContainsAny(from, "\r\n") || strings.ContainsAny(to, "\r\n") || strings.ContainsAny(subject, "\r\n") {
		return errors.New("smtp: message headers contain line breaks")
	}
	return nil
}
