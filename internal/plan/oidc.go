package plan

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/TeleCrypt-io/controlplane/internal/httpdiag"
	"github.com/TeleCrypt-io/controlplane/internal/jsonbody"
)

const (
	maxOIDCFieldBytes    = 8 << 10
	maxOIDCUsernameBytes = 255
)

// OIDCClient is Plan's MAS authorization-code + PKCE client. Browser authorization uses the
// public homeserver URL; token and userinfo calls use MAS's pod-local address.
type OIDCClient struct {
	authorizeURL, tokenURL, userinfoURL, clientID, clientSecret, redirectURI string
	httpClient                                                               *http.Client
}

func NewOIDCClient(backendPublicURL, masInternalURL, clientID, clientSecret, redirectURI string) *OIDCClient {
	backendPublicURL, masInternalURL = strings.TrimRight(backendPublicURL, "/"), strings.TrimRight(masInternalURL, "/")
	return &OIDCClient{authorizeURL: backendPublicURL + "/authorize", tokenURL: masInternalURL + "/oauth2/token", userinfoURL: masInternalURL + "/oauth2/userinfo", clientID: clientID, clientSecret: clientSecret, redirectURI: redirectURI, httpClient: &http.Client{Timeout: 10 * time.Second, Transport: noProxyTransport(), CheckRedirect: rejectRedirects}}
}

func NewPKCEPair() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func (c *OIDCClient) AuthorizeURL(state, challenge string) string {
	v := url.Values{"response_type": {"code"}, "client_id": {c.clientID}, "redirect_uri": {c.redirectURI}, "scope": {"openid"}, "state": {state}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	return c.authorizeURL + "?" + v.Encode()
}

func (c *OIDCClient) ExchangeCode(ctx context.Context, code, verifier string) (accessToken string, resultErr error) {
	if !validOIDCField(code, maxOIDCFieldBytes) || !validOIDCField(verifier, maxOIDCFieldBytes) {
		return "", fmt.Errorf("token exchange: invalid code or verifier")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {c.redirectURI}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.clientID, c.clientSecret)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", httpdiag.WrapCause("token exchange", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, readErr, closeErr := httpdiag.ReadAndClose(resp.Body)
		return "", httpdiag.NewResponseError("token exchange", resp.StatusCode, body, readErr, closeErr)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, httpdiag.WrapCause("token exchange response body close", closeErr))
		}
	}()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := jsonbody.Decode(resp.Body, &out); err != nil {
		return "", fmt.Errorf("token exchange response: %w", err)
	}
	if !validOIDCField(out.AccessToken, maxOIDCFieldBytes) {
		return "", fmt.Errorf("token exchange: empty access_token")
	}
	return out.AccessToken, nil
}

func (c *OIDCClient) Username(ctx context.Context, token string) (username string, resultErr error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.userinfoURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", httpdiag.WrapCause("userinfo", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, readErr, closeErr := httpdiag.ReadAndClose(resp.Body)
		return "", httpdiag.NewResponseError("userinfo", resp.StatusCode, body, readErr, closeErr)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, httpdiag.WrapCause("userinfo response body close", closeErr))
		}
	}()
	var out struct {
		Username string `json:"username"`
	}
	if err := jsonbody.Decode(resp.Body, &out); err != nil {
		return "", fmt.Errorf("userinfo response: %w", err)
	}
	if !validOIDCField(out.Username, maxOIDCUsernameBytes) {
		return "", fmt.Errorf("userinfo: empty username")
	}
	return out.Username, nil
}

func validOIDCField(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func rejectRedirects(*http.Request, []*http.Request) error {
	return errors.New("privileged HTTP redirects are disabled")
}
