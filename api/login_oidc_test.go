package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/gorilla/securecookie"
	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/db/sql"
	"github.com/semaphoreui/semaphore/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeOIDCIdP is a minimal OpenID Connect provider used to exercise
// Semaphore's OIDC login handlers end to end: discovery, authorize (approves
// instantly), token (returns a signed ID token) and JWKS. The ID token
// carries the claims Semaphore maps users from.
type fakeOIDCIdP struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	email    string
	issuer   string
	clientID string
	code     string
}

func newFakeOIDCIdP(t *testing.T, clientID, email string) *fakeOIDCIdP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	idp := &fakeOIDCIdP{key: key, email: email, clientID: clientID}

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                idp.issuer,
			"authorization_endpoint":                idp.issuer + "/authorize",
			"token_endpoint":                        idp.issuer + "/token",
			"jwks_uri":                              idp.issuer + "/jwks.json",
			"userinfo_endpoint":                     idp.issuer + "/userinfo",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{Key: idp.key.Public(), Algorithm: string(jose.RS256), Use: "sig"},
			},
		})
	})

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		// The fake IdP has no login screen: approve immediately.
		idp.code = fmt.Sprintf("code-%d", time.Now().UnixNano())
		redirect, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
		q := redirect.Query()
		q.Set("code", idp.code)
		q.Set("state", r.URL.Query().Get("state"))
		redirect.RawQuery = q.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, idp.code, r.PostFormValue("code"))

		signer, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.RS256, Key: idp.key},
			(&jose.SignerOptions{}).WithType("JWT"),
		)
		require.NoError(t, err)

		now := time.Now()
		claims := map[string]any{
			"iss":                idp.issuer,
			"aud":                idp.clientID,
			"sub":                "user-1",
			"email":              idp.email,
			"email_verified":     true,
			"name":               "IdP User",
			"preferred_username": "idpuser",
			"iat":                now.Unix(),
			"exp":                now.Add(time.Hour).Unix(),
		}

		raw, err := signer.Sign([]byte(mustJSON(t, claims)))
		require.NoError(t, err)

		writeJSON(w, map[string]any{
			"access_token": "at",
			"token_type":   "Bearer",
			"id_token":     raw.FullSerialize(),
		})
	})

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	idp.issuer = idp.server.URL

	return idp
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return raw
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// oidcTestEnv boots a Semaphore API server (real router + sqlite store) with
// the given IdP configured as OIDC provider "authentik", mirroring how
// cli/cmd/root.go wires the production server.
type oidcTestEnv struct {
	baseURL string
	store   *sql.SqlDb
}

func newOIDCTestEnv(t *testing.T, idp *fakeOIDCIdP) *oidcTestEnv {
	t.Helper()

	store := sql.CreateTestStore()
	t.Cleanup(func() { _ = store.Close })

	hash, err := base64.StdEncoding.DecodeString(base64.StdEncoding.EncodeToString([]byte("test-hash-key-0123456789abcdef012345")))
	require.NoError(t, err)
	util.Cookie = securecookie.New(hash, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	baseURL := "http://" + ln.Addr().String()

	// must be set before Route(): the router reads Debugging.ApiDelay and
	// WebHostURL at construction time.
	util.Config = &util.ConfigType{
		Debugging: &util.DebuggingConfig{},
		Mfa:       &util.MultifactorAuthConfig{Totp: &util.TotpConfig{}},
		WebHost:   baseURL,
		OidcProviders: map[string]util.OidcProvider{
			"authentik": {
				ClientID:      idp.clientID,
				ClientSecret:  "secret",
				RedirectURL:   baseURL + "/api/auth/oidc/authentik/redirect",
				AutoDiscovery: idp.issuer,
				Scopes:        []string{"openid", "profile", "email"},
				DisplayName:   "Fake IdP",
				// claim names are normally filled by config defaults
				// (util.ConfigType processing); struct literals must set them.
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

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), "store", db.Store(store)))
		route.ServeHTTP(w, r)
	})

	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	return &oidcTestEnv{baseURL: baseURL, store: store}
}

func (e *oidcTestEnv) client(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func get(t *testing.T, client *http.Client, rawURL string) *http.Response {
	t.Helper()
	resp, err := client.Get(rawURL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestOidcLoginRedirectsToIdP(t *testing.T) {
	idp := newFakeOIDCIdP(t, "semaphore-test", "user@rezus.cloud")
	env := newOIDCTestEnv(t, idp)
	client := env.client(t)

	resp := get(t, client, env.baseURL+"/api/auth/oidc/authentik/login")
	require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	target, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, idp.issuer+"/authorize", target.Scheme+"://"+target.Host+target.Path)
	assert.Equal(t, "semaphore-test", target.Query().Get("client_id"))
	assert.Equal(t, "code", target.Query().Get("response_type"))
	assert.NotEmpty(t, target.Query().Get("state"))

	// the CSRF state must also be dropped as a cookie (scoped to the
	// request path, like every sane Set-Cookie without an explicit Path)
	var stateCookie *http.Cookie
	semURL, _ := url.Parse(env.baseURL + "/api/auth/oidc/authentik/redirect")
	for _, c := range client.Jar.Cookies(semURL) {
		if c.Name == "oauthstate" {
			stateCookie = c
		}
	}
	require.NotNil(t, stateCookie, "oauthstate cookie must be set")
}

func TestOidcLoginUnknownProvider(t *testing.T) {
	idp := newFakeOIDCIdP(t, "semaphore-test", "user@rezus.cloud")
	env := newOIDCTestEnv(t, idp)
	client := env.client(t)

	resp := get(t, client, env.baseURL+"/api/auth/oidc/nosuch/login")
	require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	assert.True(t, strings.HasSuffix(resp.Header.Get("Location"), "/auth/login"),
		"unknown provider must land on the login page, got %s", resp.Header.Get("Location"))
}

// TestOidcFullFlowProvisionsUser drives the whole authorization-code flow:
// login redirect -> fake IdP authorize (auto-approve) -> callback -> session.
func TestOidcFullFlowProvisionsUser(t *testing.T) {
	idp := newFakeOIDCIdP(t, "semaphore-test", "user@rezus.cloud")
	env := newOIDCTestEnv(t, idp)
	client := env.client(t)

	resp := get(t, client, env.baseURL+"/api/auth/oidc/authentik/login")
	require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)

	// follow to the IdP: it approves and sends us back with code + state
	resp = get(t, client, resp.Header.Get("Location"))
	require.Equal(t, http.StatusFound, resp.StatusCode)
	callback := resp.Header.Get("Location")

	// the callback must establish a session and bounce to the web root
	resp = get(t, client, callback)
	require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	assert.True(t, strings.HasSuffix(resp.Header.Get("Location"), env.baseURL+"/") ||
		resp.Header.Get("Location") == "/",
		"successful login must redirect to the web root, got %s", resp.Header.Get("Location"))

	user, err := env.store.GetUserByLoginOrEmail("", "user@rezus.cloud")
	require.NoError(t, err, "OIDC login must provision the user")
	assert.True(t, user.External, "provisioned user must be external")
	assert.Equal(t, "user@rezus.cloud", user.Email)

	// the session cookie must grant access to the authenticated API
	authenticated := &http.Client{
		Jar: client.Jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp = get(t, authenticated, env.baseURL+"/api/user")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var me db.User
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&me))
	assert.Equal(t, user.ID, me.ID)
}

// TestOidcSecondLoginLinksSameUser: a second flow must reuse the provisioned
// user instead of creating a duplicate.
func TestOidcSecondLoginLinksSameUser(t *testing.T) {
	idp := newFakeOIDCIdP(t, "semaphore-test", "user@rezus.cloud")
	env := newOIDCTestEnv(t, idp)

	runFlow := func() {
		client := env.client(t)
		resp := get(t, client, env.baseURL+"/api/auth/oidc/authentik/login")
		resp = get(t, client, resp.Header.Get("Location"))
		resp = get(t, client, resp.Header.Get("Location"))
		require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	}

	runFlow()
	first, err := env.store.GetUserByLoginOrEmail("", "user@rezus.cloud")
	require.NoError(t, err)

	runFlow()
	second, err := env.store.GetUserByLoginOrEmail("", "user@rezus.cloud")
	require.NoError(t, err)

	assert.Equal(t, first.ID, second.ID, "second OIDC login must link to the same user")
}

// TestOidcStateMismatchRejected: a callback whose state does not match the
// oauthstate cookie must be rejected without provisioning anything.
func TestOidcStateMismatchRejected(t *testing.T) {
	idp := newFakeOIDCIdP(t, "semaphore-test", "user@rezus.cloud")
	env := newOIDCTestEnv(t, idp)
	client := env.client(t)

	resp := get(t, client, env.baseURL+"/api/auth/oidc/authentik/login")
	resp = get(t, client, resp.Header.Get("Location"))
	callback := resp.Header.Get("Location")

	// start a SECOND flow to desynchronize the oauthstate cookie
	get(t, client, env.baseURL+"/api/auth/oidc/authentik/login")

	resp = get(t, client, callback)
	require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "/auth/login",
		"state mismatch must land on the login page")

	_, err := env.store.GetUserByLoginOrEmail("", "user@rezus.cloud")
	assert.Error(t, err, "state mismatch must not provision a user")
}

// TestOidcLocalUserConflictRejected: an IdP identity colliding with a LOCAL
// (non-external) account must be rejected instead of logging into it.
func TestOidcLocalUserConflictRejected(t *testing.T) {
	idp := newFakeOIDCIdP(t, "semaphore-test", "user@rezus.cloud")
	env := newOIDCTestEnv(t, idp)

	_, err := env.store.CreateUser(db.UserWithPwd{
		User: db.User{
			Username: "localuser",
			Name:     "Local User",
			Email:    "user@rezus.cloud",
			External: false,
		},
	})
	require.NoError(t, err)

	client := env.client(t)
	resp := get(t, client, env.baseURL+"/api/auth/oidc/authentik/login")
	resp = get(t, client, resp.Header.Get("Location"))
	resp = get(t, client, resp.Header.Get("Location"))

	require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "/auth/login",
		"conflict with a local user must land on the login page")
}
