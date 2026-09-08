package janitor

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeSMTP is a minimal SMTP server for testing STARTTLS-required behaviour.
// It can be configured to advertise STARTTLS (with a self-signed cert) or not.
type fakeSMTP struct {
	listener   net.Listener
	host       string
	port       string
	startTLS   bool
	tlsConfig  *tls.Config
	gotMail    bool
	gotMessage string
}

type closeErrorConn struct {
	net.Conn
	err        error
	started    chan struct{}
	closeCalls *int
}

func (c closeErrorConn) Close() error {
	if c.started != nil {
		close(c.started)
	}
	if c.closeCalls != nil {
		(*c.closeCalls)++
	}
	return c.err
}

func newFakeSMTP(t *testing.T, advertiseSTARTTLS bool) *fakeSMTP {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	f := &fakeSMTP{
		listener: listener,
		host:     host,
		port:     port,
		startTLS: advertiseSTARTTLS,
	}
	if advertiseSTARTTLS {
		f.tlsConfig = selfSignedTLSConfig(t, host)
	}
	go f.serve()
	return f
}

func (f *fakeSMTP) serve() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeSMTP) handle(conn net.Conn) {
	defer conn.Close()
	fmt.Fprintf(conn, "220 fake.test ESMTP\r\n")
	br := bufio.NewReader(conn)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO") || strings.HasPrefix(cmd, "HELO"):
			if f.startTLS {
				fmt.Fprintf(conn, "250-fake.test\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")
			} else {
				fmt.Fprintf(conn, "250-fake.test\r\n250 AUTH PLAIN\r\n")
			}
		case strings.HasPrefix(cmd, "STARTTLS"):
			if !f.startTLS {
				fmt.Fprintf(conn, "502 Command not implemented\r\n")
				continue
			}
			fmt.Fprintf(conn, "220 Ready to start TLS\r\n")
			tlsConn := tls.Server(conn, f.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
			br = bufio.NewReader(conn)
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			fmt.Fprintf(conn, "235 2.7.0 Authentication successful\r\n")
		case strings.HasPrefix(cmd, "MAIL FROM"):
			f.gotMail = true
			fmt.Fprintf(conn, "250 OK\r\n")
		case strings.HasPrefix(cmd, "RCPT TO"):
			fmt.Fprintf(conn, "250 OK\r\n")
		case strings.HasPrefix(cmd, "DATA"):
			fmt.Fprintf(conn, "354 End data with <CR><LF>.<CR><LF>\r\n")
			var sb strings.Builder
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimSpace(line) == "." {
					break
				}
				sb.WriteString(line)
			}
			f.gotMessage = sb.String()
			fmt.Fprintf(conn, "250 OK\r\n")
		case strings.HasPrefix(cmd, "QUIT"):
			fmt.Fprintf(conn, "221 Bye\r\n")
			return
		default:
			fmt.Fprintf(conn, "502 Command not implemented\r\n")
		}
	}
}

func (f *fakeSMTP) close() {
	f.listener.Close()
}

func selfSignedTLSConfig(t *testing.T, host string) *tls.Config {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

func TestSMTPMailer_SendSucceedsWithSTARTTLS(t *testing.T) {
	srv := newFakeSMTP(t, true)
	defer srv.close()

	m := &SMTPMailer{
		Host:      srv.host,
		Port:      srv.port,
		Username:  "user",
		Password:  "pass",
		From:      "from@test",
		tlsConfig: &tls.Config{InsecureSkipVerify: true, ServerName: srv.host},
	}

	err := m.Send(context.Background(), "to@test", "Test", "body")
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	if !srv.gotMail {
		t.Error("server did not receive MAIL FROM")
	}
	if !strings.Contains(srv.gotMessage, "body") {
		t.Errorf("server did not receive message body, got: %q", srv.gotMessage)
	}
}

func TestCloseSMTPConnectionPreservesCloseFailure(t *testing.T) {
	closeErr := errors.New("SMTP connection close failed")
	if err := closeSMTPConnection(closeErrorConn{err: closeErr}); !errors.Is(err, closeErr) {
		t.Fatalf("closeSMTPConnection error = %v, want close failure", err)
	}
}

func TestStartSMTPContextClosePreservesCallbackFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	closeErr := errors.New("SMTP cancellation close failed")
	conn := closeErrorConn{err: closeErr, started: make(chan struct{})}
	finish := startSMTPContextClose(ctx, conn)
	cancel()
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("SMTP cancellation close callback did not start")
	}
	if err := finish(); !errors.Is(err, closeErr) {
		t.Fatalf("context close error = %v, want callback close failure", err)
	}
}

func TestSMTPConnectionClosesUnderlyingSocketOnce(t *testing.T) {
	closeCalls := 0
	closeErr := errors.New("SMTP connection close failed")
	conn := &smtpConnection{Conn: closeErrorConn{err: closeErr, closeCalls: &closeCalls}}
	if err := conn.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("first SMTP connection close = %v, want close failure", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("repeated SMTP connection close = %v, want nil", err)
	}
	if closeCalls != 1 {
		t.Fatalf("underlying close calls = %d, want 1", closeCalls)
	}
}

func TestSMTPMailer_SendFailsWithoutSTARTTLS(t *testing.T) {
	srv := newFakeSMTP(t, false)
	defer srv.close()

	m := &SMTPMailer{
		Host:      srv.host,
		Port:      srv.port,
		Username:  "user",
		Password:  "pass",
		From:      "from@test",
		tlsConfig: &tls.Config{InsecureSkipVerify: true, ServerName: srv.host},
	}

	err := m.Send(context.Background(), "to@test", "Test", "body")
	if err == nil {
		t.Fatal("Send succeeded without STARTTLS — should have failed")
	}
	if !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("expected STARTTLS-related error, got: %v", err)
	}
}

func TestSMTPMailer_ContextCancelsStalledGreeting(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- conn
		<-ctx.Done()
		_ = conn.Close()
	}()

	m := &SMTPMailer{Host: host, Port: port, Username: "user", Password: "pass", From: "from@test"}
	errCh := make(chan error, 1)
	go func() { errCh <- m.Send(ctx, "to@test", "Test", "body") }()
	select {
	case <-accepted:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("SMTP client did not connect")
	}
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Send succeeded after greeting cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("Send did not stop after context cancellation")
	}
}

func TestValidateSMTPMessageRejectsInjectionAndOversizedFields(t *testing.T) {
	tests := []struct {
		name          string
		from, to      string
		subject, body string
	}{
		{name: "from injection", from: "from@test\r\nBcc: attacker@test", to: "to@test", subject: "Test", body: "body"},
		{name: "subject injection", from: "from@test", to: "to@test", subject: "Test\nBcc: attacker@test", body: "body"},
		{name: "body too large", from: "from@test", to: "to@test", subject: "Test", body: strings.Repeat("x", maxSMTPBodyBytes+1)},
		{name: "header too large", from: strings.Repeat("a", maxSMTPHeaderBytes), to: "to@test", subject: "Test", body: "body"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateSMTPMessage(tt.from, tt.to, tt.subject, tt.body); err == nil {
				t.Fatal("validateSMTPMessage unexpectedly accepted unsafe or oversized message")
			}
		})
	}
}
