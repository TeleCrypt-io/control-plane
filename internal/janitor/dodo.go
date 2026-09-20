package janitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DodoReader makes one read-only provider request per scheduled Janitor run. It intentionally has
// no checkout, portal, mutation, webhook, or Cashier token-exchange method.
type DodoReader struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func NewDodoReader(baseURL, apiKey string) *DodoReader {
	return &DodoReader{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 30 * time.Second, CheckRedirect: rejectDodoRedirects},
	}
}

func (c *DodoReader) Reconcile(ctx context.Context) ([]Discrepancy, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/subscriptions", nil)
	if err != nil {
		return nil, fmt.Errorf("dodo read-only request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dodo read-only request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		return nil, fmt.Errorf("dodo read-only request: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload struct {
		Items []struct {
			ID     string `json:"subscription_id"`
			Status string `json:"status"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode dodo read-only response: %w", err)
	}
	var discrepancies []Discrepancy
	for _, item := range payload.Items {
		if item.ID == "" || item.Status == "" {
			continue
		}
		switch item.Status {
		case "past_due", "on_hold", "cancelled", "expired":
			discrepancies = append(discrepancies, Discrepancy{Subscription: item.ID, Kind: item.Status})
		}
	}
	return discrepancies, nil
}

func rejectDodoRedirects(*http.Request, []*http.Request) error {
	return fmt.Errorf("dodo read-only redirects are disabled")
}
