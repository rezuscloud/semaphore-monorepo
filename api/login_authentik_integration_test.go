//go:build integration_authentik

package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/db/sql"
	"github.com/semaphoreui/semaphore/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthentikEndToEnd proves SSO via OIDC against the real Authentik
// instance of the platform (CI job integrate-authentik):
//
//  1. idempotently ensure the test user + OIDC provider + application
//     exist on Authentik (API-driven; the pitfalls of provider creation
//     are encoded here: grant_types, property_mappings, signing_key)
//  2. boot the real Semaphore API with provider "authentik" configured
//  3. complete the authorization-code flow as a headless browser: the
//     Authentik flow-executor API logs the test user in, the authorize
//     endpoint issues the code, Semaphore's callback consumes it
//  4. assert: external user provisioned, session works, second login
//     links to the same user, state mismatch is rejected
//
// Skipped unless the AUTHENTIK_* environment is provided.
func TestAuthentikEndToEnd(t *testing.T) {
	addr := envOr("AUTHENTIK_ADDR", "https://auth.rezus.cloud")
	apiToken := os.Getenv("AUTHENTIK_API_TOKEN")
	clientID := os.Getenv("AUTHENTIK_CLIENT_ID")
	clientSecret := os.Getenv("AUTHENTIK_CLIENT_SECRET")
	testUser := envOr("AUTHENTIK_TEST_USER", "semaphore-itest")
	testPassword := os.Getenv("AUTHENTIK_TEST_PASSWORD")
	testEmail := envOr("AUTHENTIK_TEST_EMAIL", testUser+"@rezus.cloud")
	port := envOr("AUTHENTIK_TEST_PORT", "4000")

	if apiToken == "" || clientID == "" || clientSecret == "" || testPassword == "" {
		t.Skip("AUTHENTIK_API_TOKEN / AUTHENTIK_CLIENT_ID / AUTHENTIK_CLIENT_SECRET / AUTHENTIK_TEST_PASSWORD not set — skipping live Authentik test")
	}

	baseURL := "http://127.0.0.1:" + port
	redirectURI := baseURL + "/api/auth/oidc/authentik/redirect"

	// --- 1. Authentik setup (idempotent) ------------------------------
	ak := &authentikClient{t: t, addr: addr, token: apiToken}
	ak.ensureUser(testUser, "Semaphore CI Test", testEmail, testPassword)
	ak.ensureProvider("semaphore-oidc-test", clientID, clientSecret, redirectURI, testEmail)
	ak.ensureApplication("Semaphore Test", "semaphore-itest", "semaphore-oidc-test")

	// --- 2. Semaphore API (real router + sqlite store) ----------------
	store := sql.CreateTestStore()
	t.Cleanup(func() { _ = store.Close })

	hash, err := base64.StdEncoding.DecodeString(base64.StdEncoding.EncodeToString([]byte("itest-hash-key-0123456789abcdef012345")))
	require.NoError(t, err)
	util.Cookie = securecookie.New(hash, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	require.NoError(t, err, "port %s must be free (and match the registered redirect URI)", port)

	util.Config = &util.ConfigType{
		Debugging: &util.DebuggingConfig{},
		Mfa:       &util.MultifactorAuthConfig{Totp: &util.TotpConfig{}},
		WebHost:   baseURL,
		OidcProviders: map[string]util.OidcProvider{
			"authentik": {
				ClientID:      clientID,
				ClientSecret:  clientSecret,
				RedirectURL:   redirectURI,
				AutoDiscovery: addr + "/application/o/semaphore-itest/",
				Scopes:        []string{"openid", "profile", "email"},
				DisplayName:   "Authentik (rezus.cloud)",
				UsernameClaim: "preferred_username",
				NameClaim:     "name",
				EmailClaim:    "email",
			},
		},
	}

	route := Route(
		store,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), "store", db.Store(store)))
		route.ServeHTTP(w, r)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	// the login surface must advertise the provider (the UI renders its
	// button from this)
	assert.True(t, eventuallyReady(t, baseURL), "semaphore API must come up")

	// --- 3. full flow as a headless browser ---------------------------
	session := loginViaAuthentik(t, addr, baseURL, testUser, testPassword)

	userID := session.me(t, baseURL).ID
	assert.NotZero(t, userID)

	me := session.me(t, baseURL)
	assert.Equal(t, testEmail, me.Email, "user must be provisioned from the IdP email claim")
	assert.True(t, me.External, "provisioned user must be external")

	// second login must link to the same user, not duplicate it
	second := loginViaAuthentik(t, addr, baseURL, testUser, testPassword)
	assert.Equal(t, userID, second.me(t, baseURL).ID, "second SSO login must link to the same user")

	// tampered state must be rejected without a session
	rejected := rejectedStateClient(t, baseURL)
	assert.Contains(t, rejected, "/auth/login", "state mismatch must land on the login page")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func eventuallyReady(t *testing.T, baseURL string) bool {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/api/auth/login")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
			t.Logf("readiness probe: %s -> %s", baseURL+"/api/auth/login", resp.Status)
		} else {
			t.Logf("readiness probe: %v", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

// semaphoreSession is a browser with a logged-in Semaphore session.
type semaphoreSession struct {
	client *http.Client
}

func (s semaphoreSession) me(t *testing.T, baseURL string) db.User {
	t.Helper()
	resp, err := s.client.Get(baseURL + "/api/user")
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	require.Equal(t, http.StatusOK, resp.StatusCode, "session must grant /api/user")
	var u db.User
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&u))
	return u
}

func noRedirectJar(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// loginViaAuthentik performs the complete SSO dance:
//
//	Semaphore /login -> Authentik authorize -> flow-executor login
//	(identification + password) -> authorize with session -> callback.
func loginViaAuthentik(t *testing.T, addr, baseURL, user, password string) semaphoreSession {
	t.Helper()

	browser := noRedirectJar(t)

	// 1. Semaphore hands out state + oauthstate cookie
	resp := mustGet(t, browser, baseURL+"/api/auth/oidc/authentik/login")
	require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	authorizeURL := resp.Header.Get("Location")

	// 2. log into Authentik via the flow-executor API; the returned client
	// carries the authenticated IdP session
	idp := idpLogin(t, addr, user, password, authorizeURL)

	// 3. authorize with the authenticated session -> code
	resp = mustGet(t, idp, authorizeURL)
	require.Equal(t, http.StatusFound, resp.StatusCode, "authorize must issue a code, got %v %s", resp.StatusCode, bodyOf(t, resp))
	callback := resp.Header.Get("Location")
	require.Contains(t, callback, "code=", "authorize redirect must carry the code")

	// 4. Semaphore consumes the code
	resp = mustGet(t, browser, callback)
	require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	assert.Contains(t, []string{"/", baseURL + "/"}, resp.Header.Get("Location"),
		"successful SSO must land at the web root, got %s", resp.Header.Get("Location"))

	return semaphoreSession{client: browser}
}

// idpLogin authenticates at Authentik through the flow-executor API —
// the supported programmatic replacement for the login form:
//
//	GET  executor?query=<authorize-url>      -> ak-stage-identification
//	POST {identification, uid_field}         -> xak-flow-redirect{to}
//	GET  to                                  -> ak-stage-password
//	POST {password}                          -> xak-flow-redirect{to}
//	GET  to                                  -> session authenticated
func idpLogin(t *testing.T, addr, user, password, authorizeURL string) *http.Client {
	t.Helper()

	// The flow plan is bound to the RAW ?query= value: url.Values.Encode()
	// percent-encodes "/" and authentik's plan lookup then misses. Encode
	// like a browser/curl would — only the reserved characters.
	executor := addr + "/api/v3/flows/executor/default-authentication-flow/"
	full := executor + "?query=" +
		strings.NewReplacer(":", "%3A", "?", "%3F", "&", "%26", "=", "%3D", "+", "%2B").Replace(authorizeURL)

	// The flow state lives in the session cookie. Django CSRF additionally
	// requires a Referer on session-carrying POSTs over HTTPS.
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	flowClient := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	type flowResp struct {
		Component string `json:"component"`
		To        string `json:"to"`
	}

	api := func(method, u string, body any) flowResp {
		var rd io.Reader
		if body != nil {
			raw, err := json.Marshal(body)
			require.NoError(t, err)
			rd = strings.NewReader(string(raw))
		}
		req, err := http.NewRequest(method, u, rd)
		require.NoError(t, err)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Referer", addr+"/")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := flowClient.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })
		raw, _ := io.ReadAll(resp.Body)
		require.Equal(t, http.StatusOK, resp.StatusCode, "executor %s %s: %s", method, u, string(raw))
		var fr flowResp
		require.NoError(t, json.Unmarshal(raw, &fr), "executor response: %s", string(raw))
		return fr
	}

	// stage dance; the xak-flow-redirect continuations are for browsers
	fr := api(http.MethodGet, full, nil)
	require.Equal(t, "ak-stage-identification", fr.Component)

	fr = api(http.MethodPost, full, map[string]string{"component": "ak-stage-identification", "uid_field": user})
	require.Equal(t, "xak-flow-redirect", fr.Component)
	require.NotEmpty(t, fr.To)

	fr = api(http.MethodPost, full, map[string]string{"component": "ak-stage-password", "password": password})
	require.Equal(t, "xak-flow-redirect", fr.Component)
	require.NotEmpty(t, fr.To)

	// the login is only sealed by following the final continuation like a
	// browser: redirect-following while staying on the IdP host (the chain
	// ends by leaving for the relying party, which stops it)
	origin, err := url.Parse(addr)
	require.NoError(t, err)
	browser := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Host != origin.Host {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, err := http.NewRequest(http.MethodGet, addr+fr.To, nil)
	require.NoError(t, err)
	req.Header.Set("Referer", addr+"/")
	resp, err := browser.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	_, _ = io.Copy(io.Discard, resp.Body)

	return flowClient
}

// rejectedStateClient starts flow A, lets flow B overwrite the
// oauthstate cookie, then replays flow A's state against the callback;
// the CSRF check runs before the code exchange, so a fake code is fine.
func rejectedStateClient(t *testing.T, baseURL string) string {
	t.Helper()

	browser := noRedirectJar(t)

	resp := mustGet(t, browser, baseURL+"/api/auth/oidc/authentik/login")
	authorize, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	staleState := authorize.Query().Get("state")

	// second flow overwrites the oauthstate cookie
	mustGet(t, browser, baseURL+"/api/auth/oidc/authentik/login")

	callback := baseURL + "/api/auth/oidc/authentik/redirect?code=stale&state=" + url.QueryEscape(staleState)
	resp = mustGet(t, browser, callback)
	return resp.Header.Get("Location")
}

func mustGet(t *testing.T, client *http.Client, rawURL string) *http.Response {
	t.Helper()
	resp, err := client.Get(rawURL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func bodyOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	raw, _ := io.ReadAll(resp.Body)
	return string(raw)
}

// ---- Authentik API (setup) -----------------------------------------

type authentikClient struct {
	t     *testing.T
	addr  string
	token string
}

func (a *authentikClient) do(method, path string, body any) (int, []byte) {
	a.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(a.t, err)
		rd = strings.NewReader(string(raw))
	}
	req, err := http.NewRequest(method, a.addr+"/api/v3"+path, rd)
	require.NoError(a.t, err)
	req.Header.Set("Authorization", "Bearer "+a.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(a.t, err)
	a.t.Cleanup(func() { _ = resp.Body.Close() })
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

type paginated[T any] struct {
	Results []T `json:"results"`
}

func (a *authentikClient) ensureUser(username, name, email, password string) {
	a.t.Helper()

	code, raw := a.do(http.MethodGet, "/core/users/?username="+username, nil)
	require.Equal(a.t, http.StatusOK, code, "user lookup: %s", string(raw))
	var users paginated[struct {
		PK int `json:"pk"`
	}]
	require.NoError(a.t, json.Unmarshal(raw, &users))

	var pk int
	if len(users.Results) == 0 {
		code, raw = a.do(http.MethodPost, "/core/users/", map[string]any{
			"username": username, "name": name, "email": email,
			"is_active": true, "path": "users", "type": "internal", "groups": []any{},
		})
		require.Equal(a.t, http.StatusCreated, code, "user create: %s", string(raw))
		var created struct {
			PK int `json:"pk"`
		}
		require.NoError(a.t, json.Unmarshal(raw, &created))
		pk = created.PK
	} else {
		pk = users.Results[0].PK
	}

	// password is (re)set every run — tests must not depend on leftovers
	code, raw = a.do(http.MethodPost, fmt.Sprintf("/core/users/%d/set_password/", pk), map[string]string{"password": password})
	require.Equal(a.t, http.StatusNoContent, code, "set_password: %s", string(raw))
}

func (a *authentikClient) flowPK(slug string) string {
	a.t.Helper()
	code, raw := a.do(http.MethodGet, "/flows/instances/?slug="+slug, nil)
	require.Equal(a.t, http.StatusOK, code)
	var flows paginated[struct {
		PK string `json:"pk"`
	}]
	require.NoError(a.t, json.Unmarshal(raw, &flows))
	require.NotEmpty(a.t, flows.Results, "flow %s must exist", slug)
	return flows.Results[0].PK
}

func (a *authentikClient) signingKeyPK() string {
	a.t.Helper()
	code, raw := a.do(http.MethodGet, "/crypto/certificatekeypairs/?has_key=true", nil)
	require.Equal(a.t, http.StatusOK, code)
	var keys paginated[struct {
		PK   string `json:"pk"`
		Name string `json:"name"`
	}]
	require.NoError(a.t, json.Unmarshal(raw, &keys))
	require.NotEmpty(a.t, keys.Results, "a signing key must exist")
	return keys.Results[0].PK
}

func (a *authentikClient) scopeMappings() []string {
	a.t.Helper()
	code, raw := a.do(http.MethodGet, "/propertymappings/provider/scope/?managed__isnull=false", nil)
	require.Equal(a.t, http.StatusOK, code)
	var mappings paginated[struct {
		PK      string `json:"pk"`
		Managed string `json:"managed"`
	}]
	require.NoError(a.t, json.Unmarshal(raw, &mappings))
	var pks []string
	for _, m := range mappings.Results {
		if strings.Contains(m.Managed, "oauth2/scope-") {
			pks = append(pks, m.PK)
		}
	}
	require.NotEmpty(a.t, pks, "default OAuth2 scope mappings must exist")
	return pks
}

func (a *authentikClient) ensureProvider(name, clientID, clientSecret, redirectURI, email string) {
	a.t.Helper()
	_ = email // sub_mode=user_email carries the email; kept for symmetry

	body := map[string]any{
		"name":                 name,
		"authorization_flow":   a.flowPK("default-provider-authorization-implicit-consent"),
		"invalidation_flow":    a.flowPK("default-invalidation-flow"),
		"client_type":          "confidential",
		"client_id":            clientID,
		"client_secret":        clientSecret,
		"grant_types":          []string{"authorization_code", "refresh_token"}, // empty default = silent rejection
		"property_mappings":    a.scopeMappings(),                               // empty default = claim-less tokens
		"signing_key":          a.signingKeyPK(),                                // null = HS256, rejected by go-oidc
		"redirect_uris":        []map[string]any{{"matching_mode": "strict", "url": redirectURI, "redirect_uri_type": "authorization"}},
		"sub_mode":             "user_email",
		"access_code_validity": "minutes=5",
		"token_validity":       "hours=8",
	}

	code, raw := a.do(http.MethodGet, "/providers/oauth2/?name="+name, nil)
	require.Equal(a.t, http.StatusOK, code)
	var providers paginated[struct {
		PK int `json:"pk"`
	}]
	require.NoError(a.t, json.Unmarshal(raw, &providers))

	if len(providers.Results) == 0 {
		code, raw = a.do(http.MethodPost, "/providers/oauth2/", body)
		require.Equal(a.t, http.StatusCreated, code, "provider create: %s", string(raw))
	} else {
		code, raw = a.do(http.MethodPatch, fmt.Sprintf("/providers/oauth2/%d/", providers.Results[0].PK), body)
		require.Equal(a.t, http.StatusOK, code, "provider patch: %s", string(raw))
	}
}

func (a *authentikClient) ensureApplication(name, slug, providerName string) {
	a.t.Helper()

	code, raw := a.do(http.MethodGet, "/providers/oauth2/?name="+providerName, nil)
	require.Equal(a.t, http.StatusOK, code)
	var providers paginated[struct {
		PK int `json:"pk"`
	}]
	require.NoError(a.t, json.Unmarshal(raw, &providers))
	require.NotEmpty(a.t, providers.Results, "provider %s must exist", providerName)

	code, raw = a.do(http.MethodGet, "/core/applications/?slug="+slug, nil)
	require.Equal(a.t, http.StatusOK, code)
	var apps paginated[struct {
		PK string `json:"pk"`
	}]
	require.NoError(a.t, json.Unmarshal(raw, &apps))

	if len(apps.Results) == 0 {
		code, raw = a.do(http.MethodPost, "/core/applications/", map[string]any{
			"name": name, "slug": slug, "provider": providers.Results[0].PK, "meta_launch_url": "",
		})
		require.Equal(a.t, http.StatusCreated, code, "application create: %s", string(raw))
	}
}
