package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

const (
	clientID      = "b1a00492-073a-47ea-816f-4c329264a828"
	issuer        = "https://auth.x.ai"
	deviceCodeURL = issuer + "/oauth2/device/code"
	tokenURL      = issuer + "/oauth2/token"
	verifyURL     = issuer + "/oauth2/device/verify"
	approveURL    = issuer + "/oauth2/device/approve"
	scope         = "openid profile email offline_access grok-cli:access api:access conversations:read conversations:write"
)

type deviceSession struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type oauthToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
	Description  string `json:"error_description"`
}

var flowGate struct {
	sync.Mutex
	last time.Time
}

func exchangeSSO(sso, proxy string) (oauthToken, error) {
	client, err := newChromeClient(sso, proxy)
	if err != nil {
		return oauthToken{}, err
	}
	defer client.CloseIdleConnections()
	resp, body, err := doRequest(client, http.MethodGet, "https://accounts.x.ai/", nil, "")
	if err != nil {
		return oauthToken{}, fmt.Errorf("validate SSO: %w", err)
	}
	if resp.StatusCode >= 400 || strings.Contains(strings.ToLower(resp.Request.URL.String()), "sign-in") {
		return oauthToken{}, fmt.Errorf("SSO is invalid or expired")
	}
	_ = body

	form := url.Values{"client_id": {clientID}, "scope": {scope}}
	resp, body, err = doRequest(client, http.MethodPost, deviceCodeURL, strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if err != nil || resp.StatusCode != http.StatusOK {
		return oauthToken{}, fmt.Errorf("request device code: HTTP %d: %s", statusCode(resp), shortBody(body))
	}
	var session deviceSession
	if err := json.Unmarshal(body, &session); err != nil || session.DeviceCode == "" || session.UserCode == "" {
		return oauthToken{}, fmt.Errorf("invalid device code response")
	}
	if session.VerificationURIComplete == "" {
		session.VerificationURIComplete = session.VerificationURI + "?user_code=" + url.QueryEscape(session.UserCode)
	}

	flowGate.Lock()
	flowLocked := true
	defer func() {
		if flowLocked {
			flowGate.Unlock()
		}
	}()
	wait := 500*time.Millisecond - time.Since(flowGate.last)
	if wait > 0 {
		time.Sleep(wait)
	}
	flowGate.last = time.Now()
	resp, body, err = doRequest(client, http.MethodGet, session.VerificationURIComplete, nil, "")
	if err != nil || resp.StatusCode >= 400 || isRateLimited(resp, body) {
		return oauthToken{}, fmt.Errorf("open verification page failed: HTTP %d", statusCode(resp))
	}
	form = url.Values{"user_code": {session.UserCode}}
	resp, body, err = doRequest(client, http.MethodPost, verifyURL, strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if err != nil || resp.StatusCode >= 400 || isRateLimited(resp, body) {
		return oauthToken{}, fmt.Errorf("verify device failed: HTTP %d", statusCode(resp))
	}
	form = url.Values{"user_code": {session.UserCode}, "action": {"allow"}, "principal_type": {"User"}, "principal_id": {""}}
	resp, body, err = doRequest(client, http.MethodPost, approveURL, strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if err != nil || resp.StatusCode >= 400 || isRateLimited(resp, body) {
		return oauthToken{}, fmt.Errorf("approve device failed: HTTP %d", statusCode(resp))
	}
	flowGate.Unlock()
	flowLocked = false

	interval := time.Duration(session.Interval) * time.Second
	if interval < 2*time.Second {
		interval = 2 * time.Second
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		form = url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {session.DeviceCode}, "client_id": {clientID}}
		resp, body, err = doRequest(client, http.MethodPost, tokenURL, strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
		if err == nil {
			var token oauthToken
			if json.Unmarshal(body, &token) == nil {
				if token.AccessToken != "" {
					if token.ExpiresIn == 0 {
						token.ExpiresIn = 21600
					}
					return token, nil
				}
				if token.Error != "authorization_pending" && token.Error != "slow_down" && token.Error != "" {
					return oauthToken{}, fmt.Errorf("token exchange: %s %s", token.Error, token.Description)
				}
				if token.Error == "slow_down" {
					interval += 5 * time.Second
				}
			}
		}
		time.Sleep(interval)
	}
	return oauthToken{}, fmt.Errorf("token exchange timed out")
}

func newChromeClient(sso, proxy string) (tlsclient.HttpClient, error) {
	options := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(30),
		tlsclient.WithClientProfile(profiles.Chrome_131),
		tlsclient.WithRandomTLSExtensionOrder(),
		tlsclient.WithCookieJar(tlsclient.NewCookieJar()),
	}
	if proxy != "" {
		options = append(options, tlsclient.WithProxyUrl(proxy))
	}
	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), options...)
	if err != nil {
		return nil, fmt.Errorf("create Chrome TLS client: %w", err)
	}
	for _, rawURL := range []string{"https://accounts.x.ai/", "https://auth.x.ai/", "https://x.ai/"} {
		u, _ := url.Parse(rawURL)
		client.SetCookies(u, []*http.Cookie{
			{Name: "sso", Value: sso, Path: "/", Secure: true},
			{Name: "sso-rw", Value: sso, Path: "/", Secure: true},
		})
	}
	return client, nil
}

func doRequest(client tlsclient.HttpClient, method, target string, body io.Reader, contentType string) (*http.Response, []byte, error) {
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		return nil, nil, err
	}
	req.Header = http.Header{
		"accept":          {"application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		"accept-language": {"en-US,en;q=0.9"},
		"user-agent":      {"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
	}
	if contentType != "" {
		req.Header.Set("content-type", contentType)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return resp, raw, err
}

func isRateLimited(resp *http.Response, body []byte) bool {
	if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
		return true
	}
	text := strings.ToLower(string(body))
	return strings.Contains(text, "rate_limited") || strings.Contains(text, "too many requests")
}

func statusCode(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}

func shortBody(body []byte) string {
	text := strings.TrimSpace(string(body))
	if len(text) > 160 {
		text = text[:160]
	}
	return text
}

func credentialFromToken(token oauthToken) (map[string]any, string, string, string, error) {
	claims := decodeJWT(token.IDToken)
	if len(claims) == 0 {
		claims = decodeJWT(token.AccessToken)
	}
	email := stringClaim(claims, "email")
	subject := firstNonEmpty(stringClaim(claims, "sub"), stringClaim(claims, "principal_id"))
	if token.AccessToken == "" {
		return nil, "", "", "", fmt.Errorf("empty access token")
	}
	now := time.Now().UTC()
	expires := now.Add(time.Duration(token.ExpiresIn) * time.Second)
	if exp := numericClaim(claims, "exp"); exp > 0 {
		expires = time.Unix(exp, 0).UTC()
	}
	fileKey := firstNonEmpty(email, subject, strconv.FormatInt(now.UnixNano(), 10))
	fileName := "xai-" + sanitizeFilePart(fileKey) + ".json"
	credential := map[string]any{
		"type": "xai", "auth_kind": "oauth",
		"access_token": token.AccessToken, "refresh_token": token.RefreshToken, "id_token": token.IDToken,
		"token_type": firstNonEmpty(token.TokenType, "Bearer"), "expires_in": token.ExpiresIn,
		"expired": expires.Format(time.RFC3339), "last_refresh": now.Format(time.RFC3339),
		"base_url": "https://cli-chat-proxy.grok.com/v1", "token_endpoint": tokenURL, "disabled": false,
		"headers": map[string]string{
			"X-XAI-Token-Auth": "xai-grok-cli", "x-grok-client-version": "0.2.93",
			"x-grok-client-identifier": "grok-shell", "User-Agent": "grok-shell/0.2.93 (linux; x86_64)",
		},
	}
	if email != "" {
		credential["email"] = email
	}
	if subject != "" {
		credential["sub"] = subject
	}
	return credential, fileName, email, subject, nil
}

func decodeJWT(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(parts[1])
	}
	if err != nil {
		return nil
	}
	var claims map[string]any
	if json.Unmarshal(raw, &claims) != nil {
		return nil
	}
	return claims
}

func stringClaim(claims map[string]any, key string) string {
	value, _ := claims[key].(string)
	return strings.TrimSpace(value)
}

func numericClaim(claims map[string]any, key string) int64 {
	switch value := claims[key].(type) {
	case float64:
		return int64(value)
	case json.Number:
		n, _ := value.Int64()
		return n
	}
	return 0
}

var unsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9@._-]+`)

func sanitizeFilePart(value string) string {
	value = unsafeFileChars.ReplaceAllString(value, "-")
	value = strings.Trim(value, "-.")
	if value == "" {
		value = "imported-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	if len(value) > 100 {
		value = value[:100]
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
