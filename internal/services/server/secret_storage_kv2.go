package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/semaphoreui/semaphore/db"
)

// kv2Client speaks the KV v2 engine REST surface shared by OpenBao (>= 2.0)
// and HashiCorp Vault (>= 1.14 community). It uses nothing outside the
// common API surface: /v1/sys/health, /v1/auth/token/lookup-self,
// /v1/auth/approle/login, and the {mount}/data|metadata endpoints.
type kv2Client struct {
	baseURL    string
	mount      string
	namespace  string
	roleID     string // non-empty => AppRole auth; credential is the secret_id
	credential string

	token string

	httpClient *http.Client
}

const (
	kv2DefaultMount = "secret"
	kv2ValueField   = "value"
)

func newKV2Client(storage db.SecretStorage, credential string) (*kv2Client, error) {
	params := map[string]any(storage.Params)

	getString := func(key string) string {
		if v, ok := params[key]; ok {
			if s, ok := v.(string); ok {
				return strings.TrimSpace(s)
			}
		}
		return ""
	}

	rawURL := getString("url")
	if rawURL == "" {
		return nil, fmt.Errorf("storage param 'url' is required")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("storage param 'url' is not a valid URL: %s", rawURL)
	}

	mount := strings.Trim(strings.TrimSpace(getString("mount")), "/")
	if mount == "" {
		mount = kv2DefaultMount
	}

	insecure := false
	if v, ok := params["insecure_tls"]; ok {
		if b, ok := v.(bool); ok {
			insecure = b
		}
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	if insecure {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // opt-in via storage params
		}
	}

	return &kv2Client{
		baseURL:    strings.TrimRight(parsed.String(), "/"),
		mount:      mount,
		namespace:  getString("namespace"),
		roleID:     getString("role_id"),
		credential: credential,
		httpClient: httpClient,
	}, nil
}

func (c *kv2Client) do(method string, apiPath string, body any, authenticated bool) (status int, respBody []byte, err error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, c.baseURL+"/v1/"+strings.TrimPrefix(apiPath, "/"), reader)
	if err != nil {
		return 0, nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}

	if authenticated {
		if err = c.authenticate(); err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}

	return resp.StatusCode, respBody, nil
}

// authenticate resolves the session token: AppRole login when role_id is
// configured, otherwise the credential is used as a static token.
func (c *kv2Client) authenticate() error {
	if c.token != "" {
		return nil
	}

	if c.roleID == "" {
		if c.credential == "" {
			return fmt.Errorf("storage credential (token) is empty")
		}
		c.token = c.credential
		return nil
	}

	status, body, err := c.do(http.MethodPost, "auth/approle/login", map[string]string{
		"role_id":   c.roleID,
		"secret_id": c.credential,
	}, false)
	if err != nil {
		return fmt.Errorf("approle login request failed: %w", err)
	}

	var login struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
		Errors []string `json:"errors"`
	}
	if err = json.Unmarshal(body, &login); err != nil {
		return fmt.Errorf("approle login: invalid response (HTTP %d)", status)
	}

	if status != http.StatusOK || login.Auth.ClientToken == "" {
		if len(login.Errors) > 0 {
			return fmt.Errorf("approle login failed (HTTP %d): %s", status, strings.Join(login.Errors, "; "))
		}
		return fmt.Errorf("approle login failed (HTTP %d)", status)
	}

	c.token = login.Auth.ClientToken
	return nil
}

func kv2Error(status int, body []byte, context string) error {
	var parsed struct {
		Errors []string `json:"errors"`
	}
	_ = json.Unmarshal(body, &parsed)
	if len(parsed.Errors) > 0 {
		return fmt.Errorf("%s failed (HTTP %d): %s", context, status, strings.Join(parsed.Errors, "; "))
	}
	return fmt.Errorf("%s failed (HTTP %d)", context, status)
}

// Health implements SecretStorageClient. The health endpoint status codes
// are remapped with query parameters so that standby nodes count as healthy:
// 200 = active or standby, 501 = not initialized, 503 = sealed.
func (c *kv2Client) Health() error {
	status, body, err := c.do(http.MethodGet, "sys/health?standbycode=200&sealedcode=503&uninitializedcode=501&drsecondarycode=200&performancestandbycode=200", nil, false)
	if err != nil {
		return fmt.Errorf("storage health check failed: %w", err)
	}

	switch status {
	case http.StatusOK:
		return nil
	case http.StatusServiceUnavailable:
		return fmt.Errorf("storage is sealed")
	case http.StatusNotImplemented:
		return fmt.Errorf("storage is not initialized")
	default:
		return kv2Error(status, body, "storage health check")
	}
}

// ValidateCredential implements SecretStorageClient.
func (c *kv2Client) ValidateCredential() error {
	if c.roleID != "" {
		// A successful AppRole login proves both role_id and secret_id.
		c.token = ""
		return c.authenticate()
	}

	status, body, err := c.do(http.MethodGet, "auth/token/lookup-self", nil, true)
	if err != nil {
		return fmt.Errorf("token validation failed: %w", err)
	}
	if status != http.StatusOK {
		return kv2Error(status, body, "token validation")
	}
	return nil
}

func (c *kv2Client) Read(path string) (map[string]interface{}, error) {
	status, body, err := c.do(http.MethodGet, c.mount+"/data/"+cleanKV2Path(path), nil, true)
	if err != nil {
		return nil, fmt.Errorf("secret read failed: %w", err)
	}

	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, db.ErrNotFound
	case http.StatusForbidden:
		return nil, kv2Error(status, body, "secret read (permission denied)")
	default:
		return nil, kv2Error(status, body, "secret read")
	}

	var parsed struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}
	if err = json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("secret read: invalid response body")
	}
	return parsed.Data.Data, nil
}

func (c *kv2Client) Write(path string, data map[string]interface{}) error {
	status, body, err := c.do(http.MethodPost, c.mount+"/data/"+cleanKV2Path(path), map[string]interface{}{
		"data": data,
	}, true)
	if err != nil {
		return fmt.Errorf("secret write failed: %w", err)
	}
	if status != http.StatusOK {
		return kv2Error(status, body, "secret write")
	}
	return nil
}

func (c *kv2Client) Delete(path string) error {
	status, body, err := c.do(http.MethodDelete, c.mount+"/data/"+cleanKV2Path(path), nil, true)
	if err != nil {
		// Network-level errors are real failures; a missing path is not.
		return fmt.Errorf("secret delete failed: %w", err)
	}

	switch status {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	default:
		return kv2Error(status, body, "secret delete")
	}
}

func (c *kv2Client) List(prefix string) ([]string, error) {
	if strings.TrimSpace(prefix) == "" || strings.TrimSpace(prefix) == "/" {
		// Root listing needs a bare metadata endpoint.
		return c.listRecursive("")
	}
	return c.listRecursive(prefix)
}

func (c *kv2Client) listRecursive(prefix string) ([]string, error) {
	trimmed := strings.Trim(prefix, "/")
	apiPath := c.mount + "/metadata"
	if trimmed != "" {
		apiPath += "/" + trimmed
	}
	apiPath += "?list=true"

	status, body, err := c.do(http.MethodGet, apiPath, nil, true)
	if err != nil {
		return nil, fmt.Errorf("secret list failed: %w", err)
	}

	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		// Empty or missing prefix: no leaves here.
		return nil, nil
	default:
		return nil, kv2Error(status, body, "secret list")
	}

	var parsed struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err = json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("secret list: invalid response body")
	}

	var leaves []string
	for _, key := range parsed.Data.Keys {
		if strings.HasSuffix(key, "/") {
			subdir := strings.TrimSuffix(key, "/")
			subPrefix := subdir
			if trimmed != "" {
				subPrefix = trimmed + "/" + subdir
			}
			sub, err := c.listRecursive(subPrefix)
			if err != nil {
				return nil, err
			}
			leaves = append(leaves, sub...)
			continue
		}
		if trimmed != "" {
			leaves = append(leaves, trimmed+"/"+key)
		} else {
			leaves = append(leaves, key)
		}
	}

	return leaves, nil
}

// cleanKV2Path normalizes a secret path: no leading/trailing slashes, no
// traversal, no empty segments.
func cleanKV2Path(p string) string {
	segments := strings.Split(strings.TrimSpace(p), "/")
	cleaned := make([]string, 0, len(segments))
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" || segment == "." || segment == ".." {
			continue
		}
		cleaned = append(cleaned, segment)
	}
	return strings.Join(cleaned, "/")
}

// kv2DocumentValue extracts the access-key payload from a KV document.
// The payload contract: the document holds the access-key secret (JSON for
// ssh/login_password keys, plain string for string keys) under the "value"
// field.
func kv2DocumentValue(doc map[string]interface{}) (string, error) {
	raw, ok := doc[kv2ValueField]
	if !ok {
		return "", fmt.Errorf("secret document has no '%s' field", kv2ValueField)
	}
	if s, ok := raw.(string); ok {
		return s, nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("secret field '%s' is not serializable", kv2ValueField)
	}
	return string(encoded), nil
}

// splitFieldAddress parses the "path#field" addressing used by
// environment-variable references (one key per KV field). Without a "#",
// the whole document's "value" field is the payload.
func splitFieldAddress(sourceKey string) (path string, field string) {
	if idx := strings.Index(sourceKey, "#"); idx >= 0 {
		return sourceKey[:idx], sourceKey[idx+1:]
	}
	return sourceKey, ""
}
