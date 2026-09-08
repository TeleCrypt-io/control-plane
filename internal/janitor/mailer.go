package janitor

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

const (
	maxSMTPHeaderBytes = 16 << 10
	maxSMTPBodyBytes   = 1 << 20
)

// SMTPMailer sends the owner digest as plain text over a TLS-required SMTP connection.
// It negotiates STARTTLS explicitly and fails closed if the server does not advertise STARTTLS
// or if the TLS handshake fails — it never authenticates or sends in plaintext. Authentication
// uses smtp.PlainAuth only after a successful STARTTLS upgrade. Every SMTP operation is bounded
// by the same hard deadline and canceled when the request context ends. Certificate verification
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
	const timeout = 30 * time.Second
	addr := net.JoinHostPort(m.Host, m.Port)

	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	dialTimeout := time.Until(deadline)
	if dialTimeout <= 0 {
		return errors.New("smtp: deadline exceeded")
	}
	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp dial %s: %w", addr, err)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return errors.Join(fmt.Errorf("smtp: set connection deadline: %w", err), closeSMTPConnection(conn))
	}
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()

	client, err := smtp.NewClient(conn, m.Host)
	if err != nil {
		return errors.Join(fmt.Errorf("smtp new client: %w", err), closeSMTPConnection(conn))
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

func validateSMTPMessage(from, to, subject, body string) error {
	if from == "" || to == "" || subject == "" {
		return errors.New("smtp: message headers must be non-empty")
	}
	if strings.ContainsAny(from, "\r\n") || strings.ContainsAny(to, "\r\n") || strings.ContainsAny(subject, "\r\n") {
		return errors.New("smtp: message headers contain line breaks")
	}
	if len(body) > maxSMTPBodyBytes {
		return errors.New("smtp: message body exceeds limit")
	}
	header := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n", from, to, subject)
	if len(header) > maxSMTPHeaderBytes {
		return errors.New("smtp: message headers exceed limit")
	}
	return nil
}
