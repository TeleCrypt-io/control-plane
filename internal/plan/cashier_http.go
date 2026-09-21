package plan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/httpdiag"
	"github.com/TeleCrypt-io/controlplane/internal/jsonbody"
)

const (
	planMXIDHeader = "X-TeleCrypt-MXID"
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
	httpClient *http.Client
}

func NewHTTPCashierClient(baseURL string, httpClient *http.Client) (*HTTPCashierClient, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil || parsedURL.Scheme != "http" || parsedURL.Host == "" || parsedURL.User != nil ||
		(parsedURL.Path != "" && parsedURL.Path != "/") || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return nil, fmt.Errorf("Cashier URL must be an HTTP origin")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second, Transport: noProxyTransport()}
	}
	// Copy injected clients so the transport remains a test seam while redirect policy is
	// controlled by this private client.
	clientCopy := *httpClient
	if clientCopy.Timeout == 0 {
		clientCopy.Timeout = 15 * time.Second
	}
	clientCopy.CheckRedirect = rejectRedirects
	clientCopy.Transport = noProxyRoundTripper(clientCopy.Transport)
	return &HTTPCashierClient{baseURL: strings.TrimRight(baseURL, "/"), httpClient: &clientCopy}, nil
}

func (c *HTTPCashierClient) PlanState(ctx context.Context, principal Principal) (PlanState, error) {
	var response struct {
		Plan    *Plan    `json:"plan"`
		Members []Member `json:"members"`
	}
	err := c.do(ctx, principal, http.MethodGet, "/internal/cashier/plan/state", nil, &response, http.StatusOK)
	return PlanState{Plan: response.Plan, Members: response.Members}, err
}

func (c *HTTPCashierClient) AttachMember(ctx context.Context, p Principal, mxid string) error {
	body, err := json.Marshal(struct {
		MXID string `json:"mxid"`
	}{MXID: mxid})
	if err != nil {
		return err
	}
	return c.do(ctx, p, http.MethodPost, "/internal/cashier/team/members/add", body, nil, http.StatusNoContent)
}

func (c *HTTPCashierClient) RemoveMember(ctx context.Context, p Principal, mxid string) error {
	// Keep the slash escaped on the wire so it remains part of the {mxid} value.
	requestPath := "/internal/cashier/team/members/" + url.PathEscape(mxid) + "/remove"
	return c.do(ctx, p, http.MethodPost, requestPath, nil, nil, http.StatusNoContent)
}

func (c *HTTPCashierClient) LeaveMember(ctx context.Context, p Principal) error {
	return c.do(ctx, p, http.MethodPost, "/internal/cashier/team/members/leave", nil, nil, http.StatusNoContent)
}

func (c *HTTPCashierClient) do(ctx context.Context, principal Principal, method, path string, body []byte, result any, expectedStatuses ...int) (resultErr error) {
	if principal.MXID == "" {
		return fmt.Errorf("missing Plan principal")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create cashier request: %w", err)
	}
	req.Header.Set(planMXIDHeader, principal.MXID)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	response, err := c.httpClient.Do(req)
	if err != nil {
		return httpdiag.WrapCause("call cashier", err)
	}
	if !acceptsCashierStatus(response.StatusCode, expectedStatuses) {
		body, readErr, closeErr := httpdiag.ReadAndClose(response.Body)
		statusErr := &CashierError{StatusCode: response.StatusCode, Message: body}
		return errors.Join(statusErr, httpdiag.NewResponseError("Cashier error response", response.StatusCode, body, readErr, closeErr))
	}
	if result == nil {
		body, readErr, closeErr := httpdiag.ReadAndClose(response.Body)
		if readErr != nil || closeErr != nil {
			return httpdiag.NewResponseError("read Cashier response", response.StatusCode, body, readErr, closeErr)
		}
		if body != "" {
			return httpdiag.NewResponseError("cashier returned unexpected response body", response.StatusCode, body, nil, nil)
		}
		return nil
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, httpdiag.WrapCause("close Cashier response body", closeErr))
		}
	}()
	if err := jsonbody.Decode(response.Body, result); err != nil {
		return fmt.Errorf("decode cashier response: %w", err)
	}
	return nil
}

type CashierError struct {
	StatusCode int
	Message    string
}

func (e *CashierError) Error() string { return fmt.Sprintf("cashier returned %d", e.StatusCode) }
