package janitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/httpdiag"
	"github.com/TeleCrypt-io/controlplane/internal/jsonbody"
)

const cashierJanitorAPI = "http://127.0.0.1:9011/internal/cashier/janitor"

type LifecycleAction struct {
	MXID   string    `json:"mxid"`
	Action string    `json:"action"`
	DueAt  time.Time `json:"due_at"`
}

type SubscriptionSnapshot struct {
	SubscriptionID    string `json:"subscription_id"`
	Status            string `json:"status"`
	ProviderProductID string `json:"provider_product_id"`
	TeamID            string `json:"team_id"`
}

type DigestCursor struct {
	CreatedAt time.Time `json:"created_at"`
	EmailID   string    `json:"email_id"`
}

func (c DigestCursor) Valid() bool {
	if c.CreatedAt.IsZero() || len(c.EmailID) != 26 || c.EmailID[0] > '7' {
		return false
	}
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for _, r := range c.EmailID {
		if !strings.ContainsRune(alphabet, r) {
			return false
		}
	}
	return true
}

type cashierAPI interface {
	SyncLifecycleAccount(context.Context, string, time.Time) error
	LifecycleActions(context.Context) ([]LifecycleAction, error)
	ExecuteSuspension(context.Context, string) (bool, error)
	StartRemoval(context.Context, string) (bool, error)
	FinishRemoval(context.Context, string) (bool, error)
	ProviderSubscriptionSnapshot(context.Context) ([]SubscriptionSnapshot, error)
	JanitorDigestCursor(context.Context) (DigestCursor, bool, error)
	SetJanitorDigestCursor(context.Context, DigestCursor) error
}

type CashierClient struct {
	baseURL      string
	serviceToken string
	http         *http.Client
}

func NewCashierClient(serviceToken string) *CashierClient {
	return &CashierClient{
		baseURL:      cashierJanitorAPI,
		serviceToken: serviceToken,
		http: &http.Client{
			Timeout:   75 * time.Second,
			Transport: noProxyTransport(),
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("Cashier Janitor redirects are disabled")
			},
		},
	}
}

type accountSyncRequest struct {
	MXID      string    `json:"mxid"`
	CreatedAt time.Time `json:"created_at"`
}

type accountRequest struct {
	MXID string `json:"mxid"`
}

type actionResult struct {
	Applied bool `json:"applied"`
}

type cursorResult struct {
	Found  bool          `json:"found"`
	Cursor *DigestCursor `json:"cursor,omitempty"`
}

func (c *CashierClient) SyncLifecycleAccount(ctx context.Context, mxid string, createdAt time.Time) error {
	return c.do(ctx, http.MethodPost, "/account-sync", accountSyncRequest{MXID: mxid, CreatedAt: createdAt}, nil)
}

func (c *CashierClient) LifecycleActions(ctx context.Context) ([]LifecycleAction, error) {
	var actions []LifecycleAction
	err := c.do(ctx, http.MethodGet, "/actions", nil, &actions)
	return actions, err
}

func (c *CashierClient) ExecuteSuspension(ctx context.Context, mxid string) (bool, error) {
	var result actionResult
	err := c.do(ctx, http.MethodPost, "/suspend", accountRequest{MXID: mxid}, &result)
	return result.Applied, err
}

func (c *CashierClient) StartRemoval(ctx context.Context, mxid string) (bool, error) {
	var result actionResult
	err := c.do(ctx, http.MethodPost, "/start-removal", accountRequest{MXID: mxid}, &result)
	return result.Applied, err
}

func (c *CashierClient) FinishRemoval(ctx context.Context, mxid string) (bool, error) {
	var result actionResult
	err := c.do(ctx, http.MethodPost, "/finish-removal", accountRequest{MXID: mxid}, &result)
	return result.Applied, err
}

func (c *CashierClient) ProviderSubscriptionSnapshot(ctx context.Context) ([]SubscriptionSnapshot, error) {
	var subscriptions []SubscriptionSnapshot
	err := c.do(ctx, http.MethodGet, "/subscriptions", nil, &subscriptions)
	return subscriptions, err
}

func (c *CashierClient) JanitorDigestCursor(ctx context.Context) (DigestCursor, bool, error) {
	var result cursorResult
	if err := c.do(ctx, http.MethodGet, "/digest-cursor", nil, &result); err != nil {
		return DigestCursor{}, false, err
	}
	if !result.Found {
		return DigestCursor{}, false, nil
	}
	if result.Cursor == nil {
		return DigestCursor{}, false, fmt.Errorf("Cashier returned a missing digest cursor")
	}
	return *result.Cursor, true, nil
}

func (c *CashierClient) SetJanitorDigestCursor(ctx context.Context, cursor DigestCursor) error {
	return c.do(ctx, http.MethodPut, "/digest-cursor", cursor, nil)
}

func (c *CashierClient) do(ctx context.Context, method, path string, input, output any) error {
	var body *bytes.Reader
	if input == nil {
		body = bytes.NewReader(nil)
	} else {
		encoded, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("encode Cashier Janitor request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("create Cashier Janitor request: %w", err)
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.serviceToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return httpdiag.WrapCause("Cashier Janitor request "+path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseBody, readErr, closeErr := httpdiag.ReadAndClose(resp.Body)
		return httpdiag.NewResponseError("Cashier Janitor "+path, resp.StatusCode, responseBody, readErr, closeErr)
	}
	if output == nil {
		readErr, closeErr := httpdiag.DrainAndClose(resp.Body)
		if readErr != nil || closeErr != nil {
			return errors.Join(httpdiag.WrapCause("Cashier Janitor response body read", readErr), httpdiag.WrapCause("Cashier Janitor response body close", closeErr))
		}
		return nil
	}
	decodeErr := jsonbody.Decode(resp.Body, output)
	closeErr := resp.Body.Close()
	if decodeErr != nil || closeErr != nil {
		return errors.Join(httpdiag.WrapCause("decode Cashier Janitor response", decodeErr), httpdiag.WrapCause("Cashier Janitor response body close", closeErr))
	}
	return nil
}

func noProxyTransport() http.RoundTripper {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Transport{DialContext: (&net.Dialer{Timeout: 15 * time.Second}).DialContext}
	}
	transport = transport.Clone()
	transport.Proxy = nil
	return transport
}

var _ cashierAPI = (*CashierClient)(nil)
