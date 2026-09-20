// Package synapseadmin contains the narrow Synapse admin operations Janitor needs for account
// lifecycle maintenance. It is never constructed by Plan or Registration.
package synapseadmin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 30 * time.Second, CheckRedirect: rejectRedirects},
	}
}

// SuspendUser uses Synapse's native suspension state. MAS login remains available while this
// state is true, allowing a user to recover through Plan.
func (c *Client) SuspendUser(ctx context.Context, userID string, suspended bool) error {
	if userID == "" || !strings.HasPrefix(userID, "@") {
		return errors.New("synapseadmin: invalid user ID")
	}
	body, err := json.Marshal(map[string]bool{"suspend": suspended})
	if err != nil {
		return fmt.Errorf("synapseadmin: encode suspension request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		c.baseURL+"/_synapse/admin/v1/suspend/"+url.PathEscape(userID), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("synapseadmin: create suspension request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("synapseadmin: suspend user: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		return fmt.Errorf("synapseadmin: suspend user: status %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}
	return nil
}

func rejectRedirects(*http.Request, []*http.Request) error {
	return errors.New("synapseadmin redirects are disabled")
}
