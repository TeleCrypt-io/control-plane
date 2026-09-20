package janitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
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

type ProviderSubscription struct {
	SubscriptionID    string
	Status            string
	ProviderProductID string
	TeamID            string
}

func (c *DodoReader) Subscriptions(ctx context.Context) ([]ProviderSubscription, error) {
	var subscriptions []ProviderSubscription
	const pageSize = 100
	for pageNumber := 0; ; pageNumber++ {
		query := url.Values{}
		query.Set("page_size", strconv.Itoa(pageSize))
		query.Set("page_number", strconv.Itoa(pageNumber))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/subscriptions?"+query.Encode(), nil)
		if err != nil {
			return nil, fmt.Errorf("dodo read-only request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("dodo read-only request: %w", err)
		}
		var payload struct {
			Items []struct {
				ID        string         `json:"subscription_id"`
				Status    string         `json:"status"`
				ProductID string         `json:"product_id"`
				Metadata  map[string]any `json:"metadata"`
			} `json:"items"`
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
			resp.Body.Close()
			return nil, fmt.Errorf("dodo read-only request: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("decode dodo read-only response: %w", err)
		}
		resp.Body.Close()
		for _, item := range payload.Items {
			if item.ID == "" || item.Status == "" {
				continue
			}
			teamID, _ := item.Metadata["team_id"].(string)
			subscriptions = append(subscriptions, ProviderSubscription{SubscriptionID: item.ID, Status: item.Status, ProviderProductID: item.ProductID, TeamID: teamID})
		}
		if len(payload.Items) < pageSize {
			break
		}
	}
	return subscriptions, nil
}

func rejectDodoRedirects(*http.Request, []*http.Request) error {
	return fmt.Errorf("dodo read-only redirects are disabled")
}
