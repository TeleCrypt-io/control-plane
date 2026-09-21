package plan

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	sessionCookieName = "tc_plan_session"
	oauthStateCookie  = "tc_plan_oauth_state"
	oauthPKCECookie   = "tc_plan_oauth_pkce"
	oauthIntentCookie = "tc_plan_oauth_intent"
	oauthIntentMaxAge = 10 * time.Minute
)

var errUnauthorized = errors.New("unauthorized")

// Session holds Plan's browser-session signing key and the exact homeserver identity it serves.
// It is deliberately Plan-owned rather than shared with Cashier: Cashier receives only the
// authenticated Matrix identity over the fixed private pod-local connection.
type Session struct {
	key        []byte
	serverName string
}

func NewSession(key, serverName string) *Session {
	return &Session{key: []byte(key), serverName: serverName}
}

func (s *Session) Set(w http.ResponseWriter, mxid string) {
	exp := time.Now().Add(7 * 24 * time.Hour)
	payload := fmt.Sprintf("%s|%d", mxid, exp.Unix())
	value := base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + s.sign(payload)))
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: value, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: int((7 * 24 * time.Hour).Seconds())})
}

func (s *Session) MXID(r *http.Request) (string, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", errUnauthorized
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return "", errUnauthorized
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 || !hmac.Equal([]byte(parts[2]), []byte(s.sign(parts[0]+"|"+parts[1]))) {
		return "", errUnauthorized
	}
	if !validSessionMXID(parts[0], s.serverName) {
		return "", errUnauthorized
	}
	var exp int64
	if _, err := fmt.Sscan(parts[1], &exp); err != nil || exp <= 0 || time.Now().Unix() > exp {
		return "", errUnauthorized
	}
	return parts[0], nil
}

func validSessionMXID(mxid, expectedServerName string) bool {
	if len(mxid) == 0 || len(mxid) > 255 || !strings.HasPrefix(mxid, "@") || expectedServerName == "" {
		return false
	}
	parts := strings.SplitN(strings.TrimPrefix(mxid, "@"), ":", 2)
	if len(parts) != 2 || parts[1] != expectedServerName || !validateLocalpart(parts[0]) {
		return false
	}
	for _, r := range parts[1] {
		if r == '/' || r == '?' || r == '#' || r == '@' || r == ' ' || r == '\t' || r == '\r' || r == '\n' || r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (s *Session) sign(payload string) string {
	m := hmac.New(sha256.New, s.key)
	_, _ = m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func setOAuthCookies(w http.ResponseWriter, state, verifier string) {
	for _, spec := range []struct{ name, value string }{{oauthStateCookie, state}, {oauthPKCECookie, verifier}, {oauthIntentCookie, fmt.Sprintf("%d", time.Now().Unix())}} {
		http.SetCookie(w, &http.Cookie{Name: spec.name, Value: spec.value, Path: "/plan", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	}
}

func readOAuthCookie(r *http.Request, name string) (string, error) {
	c, err := r.Cookie(name)
	if err != nil || c.Value == "" {
		return "", errUnauthorized
	}
	return c.Value, nil
}

func readOAuthIntent(r *http.Request) error {
	value, err := readOAuthCookie(r, oauthIntentCookie)
	if err != nil {
		return errUnauthorized
	}
	createdAt, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return errUnauthorized
	}
	age := time.Since(time.Unix(createdAt, 0))
	if age < 0 || age > oauthIntentMaxAge {
		return errUnauthorized
	}
	return nil
}

func clearOAuthCookies(w http.ResponseWriter) {
	for _, name := range []string{oauthStateCookie, oauthPKCECookie, oauthIntentCookie} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/plan", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	}
}
