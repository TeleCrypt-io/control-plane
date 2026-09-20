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
	"strconv"
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

// SetUserType is deliberately narrower than Synapse's general admin update API:
// Janitor may only publish the Free/suspended projection, never an entitlement.
func (c *Client) SetUserType(ctx context.Context, userID, userType string) error {
	if userType != "wild" {
		return fmt.Errorf("synapseadmin: unsupported lifecycle user_type %q", userType)
	}
	body, err := json.Marshal(map[string]string{"user_type": userType})
	if err != nil {
		return fmt.Errorf("synapseadmin: encode user_type request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		c.baseURL+"/_synapse/admin/v2/users/"+url.PathEscape(userID), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("synapseadmin: create user_type request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("synapseadmin: set user_type: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		return fmt.Errorf("synapseadmin: set user_type: status %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}
	return nil
}

func (c *Client) ReadUserType(ctx context.Context, userID string) (*string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/_synapse/admin/v2/users/"+url.PathEscape(userID), nil)
	if err != nil {
		return nil, fmt.Errorf("synapseadmin: create user_type read request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("synapseadmin: read user_type: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		return nil, fmt.Errorf("synapseadmin: read user_type: status %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}
	var payload struct {
		UserType *string `json:"user_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("synapseadmin: decode user_type: %w", err)
	}
	return payload.UserType, nil
}

// DeleteAllMedia removes local media in batches. The endpoint returns the
// remaining total; restarting at offset zero avoids skipping rows as each batch
// is deleted.
func (c *Client) DeleteAllMedia(ctx context.Context, userID string) error {
	if userID == "" || !strings.HasPrefix(userID, "@") {
		return errors.New("synapseadmin: invalid media owner")
	}
	for {
		query := url.Values{"from": {"0"}, "limit": {strconv.Itoa(100)}}
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
			c.baseURL+"/_synapse/admin/v1/users/"+url.PathEscape(userID)+"/media?"+query.Encode(), nil)
		if err != nil {
			return fmt.Errorf("synapseadmin: create media deletion request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		resp, err := c.http.Do(req)
		if err != nil {
			return fmt.Errorf("synapseadmin: delete media: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			detail, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
			resp.Body.Close()
			return fmt.Errorf("synapseadmin: delete media: status %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
		}
		var result struct {
			Deleted int `json:"deleted_media"`
			Total   int `json:"total"`
		}
		err = json.NewDecoder(resp.Body).Decode(&result)
		closeErr := resp.Body.Close()
		if err != nil {
			return fmt.Errorf("synapseadmin: decode media deletion response: %w", err)
		}
		if closeErr != nil {
			return fmt.Errorf("synapseadmin: close media deletion response: %w", closeErr)
		}
		if result.Total <= 0 {
			return nil
		}
		if result.Deleted <= 0 {
			return fmt.Errorf("synapseadmin: media deletion made no progress with %d remaining", result.Total)
		}
	}
}

func rejectRedirects(*http.Request, []*http.Request) error {
	return errors.New("synapseadmin redirects are disabled")
}
