package plan

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/httpdiag"
	"github.com/TeleCrypt-io/controlplane/internal/jsonbody"
	"github.com/google/uuid"
)

const (
	planAssertionAudience = "telecrypt-cashier"
	planRequestIDHeader   = "X-TeleCrypt-Request-ID"
)

func acceptsCashierStatus(status int, expectedStatuses []int) bool {
	for _, expectedStatus := range expectedStatuses {
		if status == expectedStatus {
			return true
		}
	}
	return false
}

// HTTPCashierClient is the sole Plan-to-Cashier transport. It is deliberately limited to the
// CashierClient interface, so public Plan code cannot gain Dodo, Synapse, or database access.
type HTTPCashierClient struct {
	baseURL    string
	privateKey ed25519.PrivateKey
	httpClient *http.Client
}

func NewHTTPCashierClient(baseURL, encodedPrivateKey string, httpClient *http.Client) (*HTTPCashierClient, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil || parsedURL.Scheme != "http" || parsedURL.Host == "" || parsedURL.User != nil ||
		(parsedURL.Path != "" && parsedURL.Path != "/") || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return nil, fmt.Errorf("Cashier URL must be an HTTP origin")
	}
	key, err := base64.RawURLEncoding.DecodeString(encodedPrivateKey)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("PLAN_ASSERTION_PRIVATE_KEY must be a raw URL-safe base64 Ed25519 private key")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second, Transport: noProxyTransport()}
	}
	// Copy injected clients so the transport remains a test seam while redirect policy is
	// controlled by this privileged client. A redirect would otherwise replay the signed
	// assertion to an untrusted origin.
	clientCopy := *httpClient
	if clientCopy.Timeout == 0 {
		clientCopy.Timeout = 15 * time.Second
	}
	clientCopy.CheckRedirect = rejectRedirects
	clientCopy.Transport = noProxyRoundTripper(clientCopy.Transport)
	return &HTTPCashierClient{baseURL: strings.TrimRight(baseURL, "/"), privateKey: ed25519.PrivateKey(key), httpClient: &clientCopy}, nil
}

func (c *HTTPCashierClient) PlanState(ctx context.Context, principal Principal) (PlanState, error) {
	var response struct {
		Plan  *Plan  `json:"plan"`
		Seats []Seat `json:"seats"`
	}
	err := c.do(ctx, principal, http.MethodGet, "/internal/v1/plan-state", uuid.NewString(), nil, &response, http.StatusOK)
	return PlanState{Plan: response.Plan, Seats: response.Seats}, err
}

// CreatePlan invokes Cashier's private plan-creation endpoint. The private team storage model is
// not exposed through the public Plan API.
func (c *HTTPCashierClient) CreatePlan(ctx context.Context, p Principal, requestID string) error {
	return c.do(ctx, p, http.MethodPost, "/internal/v1/teams", requestID, []byte(`{}`), nil, http.StatusCreated, http.StatusNoContent)
}

func (c *HTTPCashierClient) AttachSeat(ctx context.Context, p Principal, requestID, mxid string) error {
	body, err := json.Marshal(struct {
		MXID string `json:"mxid"`
	}{MXID: mxid})
	if err != nil {
		return err
	}
	return c.do(ctx, p, http.MethodPost, "/internal/v1/team/seats", requestID, body, nil, http.StatusNoContent)
}

func (c *HTTPCashierClient) RemoveSeat(ctx context.Context, p Principal, requestID, mxid string) error {
	// Keep the slash escaped on the wire so it remains part of the {mxid} value. Cashier
	// authenticates against r.URL.EscapedPath(), so sign the exact canonical path sent on the wire.
	requestPath := "/internal/v1/team/seats/" + url.PathEscape(mxid)
	return c.do(ctx, p, http.MethodDelete, requestPath, requestID, nil, nil, http.StatusNoContent)
}

func (c *HTTPCashierClient) StartCheckout(ctx context.Context, p Principal, requestID string, quantity int) (string, error) {
	var response struct {
		PaymentLink string `json:"payment_link"`
	}
	body, err := json.Marshal(struct {
		Quantity int `json:"quantity"`
	}{Quantity: quantity})
	if err != nil {
		return "", err
	}
	err = c.do(ctx, p, http.MethodPost, "/internal/v1/team/checkout", requestID, body, &response, http.StatusOK)
	return response.PaymentLink, err
}

func (c *HTTPCashierClient) OpenCustomerPortal(ctx context.Context, p Principal, requestID string) (string, error) {
	var response struct {
		Link string `json:"link"`
	}
	err := c.do(ctx, p, http.MethodPost, "/internal/v1/team/portal", requestID, []byte(`{}`), &response, http.StatusOK)
	return response.Link, err
}

func (c *HTTPCashierClient) ChangeSeatCount(ctx context.Context, p Principal, requestID string, quantity int) error {
	body, err := json.Marshal(struct {
		Quantity int `json:"quantity"`
	}{Quantity: quantity})
	if err != nil {
		return err
	}
	return c.do(ctx, p, http.MethodPost, "/internal/v1/team/seat-count", requestID, body, nil, http.StatusNoContent)
}

func (c *HTTPCashierClient) do(ctx context.Context, principal Principal, method, path, requestID string, body []byte, result any, expectedStatuses ...int) (resultErr error) {
	if principal.MXID == "" {
		return fmt.Errorf("missing Plan principal")
	}
	if _, err := uuid.Parse(requestID); err != nil {
		return fmt.Errorf("invalid Plan request ID")
	}
	assertion, err := c.assertion(principal.MXID, method, path, requestID, body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create cashier request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+assertion)
	if method != http.MethodGet {
		req.Header.Set(planRequestIDHeader, requestID)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	response, err := c.httpClient.Do(req)
	if err != nil {
		return httpdiag.WrapCause("call cashier", err, assertion, principal.MXID, requestID, path)
	}
	redactions := []string{assertion, principal.MXID, requestID, path}
	if !acceptsCashierStatus(response.StatusCode, expectedStatuses) {
		body, readErr, closeErr := httpdiag.ReadAndClose(response.Body, redactions...)
		statusErr := &CashierError{StatusCode: response.StatusCode, Message: body}
		return errors.Join(statusErr, httpdiag.NewResponseError("Cashier error response", response.StatusCode, body, readErr, closeErr, redactions...))
	}
	if result == nil {
		body, readErr, closeErr := httpdiag.ReadAndClose(response.Body, redactions...)
		if readErr != nil || closeErr != nil {
			return httpdiag.NewResponseError("read Cashier response", response.StatusCode, body, readErr, closeErr, redactions...)
		}
		if body != "" {
			return httpdiag.NewResponseError("cashier returned unexpected response body", response.StatusCode, body, nil, nil, redactions...)
		}
		return nil
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, httpdiag.WrapCause("close Cashier response body", closeErr, redactions...))
		}
	}()
	if err := jsonbody.Decode(response.Body, result, redactions...); err != nil {
		return fmt.Errorf("decode cashier response: %w", err)
	}
	return nil
}

type CashierError struct {
	StatusCode int
	Message    string
}

func (e *CashierError) Error() string { return fmt.Sprintf("cashier returned %d", e.StatusCode) }

func (c *HTTPCashierClient) assertion(subject, method, path, requestID string, body []byte) (string, error) {
	sum := sha256.Sum256(body)
	payload, err := json.Marshal(struct {
		Subject    string `json:"sub"`
		Audience   string `json:"aud"`
		Expires    int64  `json:"exp"`
		Method     string `json:"method"`
		Path       string `json:"path"`
		RequestID  string `json:"request_id"`
		BodySHA256 string `json:"body_sha256"`
	}{subject, planAssertionAudience, time.Now().Add(time.Minute).Unix(), method, path, requestID, base64.RawURLEncoding.EncodeToString(sum[:])})
	if err != nil {
		return "", fmt.Errorf("marshal Plan assertion: %w", err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := header + "." + encodedPayload
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.privateKey, []byte(signingInput))), nil
}
