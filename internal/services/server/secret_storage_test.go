package server_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/db/sql"
	featsvc "github.com/semaphoreui/semaphore/internal/services/server"
	serversvc "github.com/semaphoreui/semaphore/services/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeKV2 is a minimal OpenBao/Vault KV v2 REST fake: token + AppRole auth,
// sys/health, data read/write/delete, metadata list.
type fakeKV2 struct {
	mu         sync.Mutex
	docs       map[string]map[string]interface{} // path -> document
	tokens     map[string]bool
	approle    map[string]string // "roleID:secretID" -> token
	sealed     bool
	namespaces []string
	lastToken  string
}

func newFakeKV2() *fakeKV2 {
	return &fakeKV2{
		docs:    map[string]map[string]interface{}{},
		tokens:  map[string]bool{"good-token": true},
		approle: map[string]string{"role-1:secret-1": "app-token"},
	}
}

func (f *fakeKV2) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()

		if ns := r.Header.Get("X-Vault-Namespace"); ns != "" {
			f.namespaces = append(f.namespaces, ns)
		}
		f.lastToken = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/v1/sys/health":
			if f.sealed {
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]any{"sealed": true})
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"initialized": true, "sealed": false})

		case r.URL.Path == "/v1/auth/token/lookup-self":
			if !f.tokens[f.lastToken] {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"errors":["bad token"]}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"id":"test"}}`))

		case r.URL.Path == "/v1/auth/approle/login":
			var body struct {
				RoleID   string `json:"role_id"`
				SecretID string `json:"secret_id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if token, ok := f.approle[body.RoleID+":"+body.SecretID]; ok {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(fmt.Sprintf(`{"auth":{"client_token":%q}}`, token)))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"errors":["invalid role or secret id"]}`))

		case strings.HasPrefix(r.URL.Path, "/v1/secret/data/"):
			path := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")
			switch r.Method {
			case http.MethodGet:
				if doc, ok := f.docs[path]; ok {
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"data": map[string]any{"data": doc, "metadata": map[string]any{"version": 1}},
					})
					return
				}
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":["not found"]}`))
			case http.MethodPost:
				var body struct {
					Data map[string]interface{} `json:"data"`
				}
				_ = json.NewDecoder(r.Body).Decode(&body)
				f.docs[path] = body.Data
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":{"version":1}}`))
			case http.MethodDelete:
				delete(f.docs, path)
				w.WriteHeader(http.StatusNoContent)
			}

		case r.URL.Path == "/v1/secret/metadata" || strings.HasPrefix(r.URL.Path, "/v1/secret/metadata/"):
			if r.URL.Query().Get("list") != "true" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			prefix := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/secret/metadata"), "/")
			entries := map[string]bool{}
			found := false
			for docPath := range f.docs {
				var rest string
				if prefix == "" {
					rest = docPath
				} else {
					if !strings.HasPrefix(docPath+"/", prefix+"/") {
						continue
					}
					rest = strings.TrimPrefix(docPath, prefix)
					rest = strings.TrimPrefix(rest, "/")
				}
				found = true
				segments := strings.Split(rest, "/")
				if len(segments) == 1 {
					entries[segments[0]] = true
				} else {
					entries[segments[0]+"/"] = true
				}
			}
			if !found && prefix != "" {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":["not found"]}`))
				return
			}
			keys := make([]string, 0, len(entries))
			for key := range entries {
				keys = append(keys, key)
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": keys}})

		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":["unknown path"]}`))
		}
	})
}

func (f *fakeKV2) seed(path string, doc map[string]interface{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.docs[path] = doc
}

func (f *fakeKV2) doc(path string) map[string]interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.docs[path]
}

func (f *fakeKV2) deleteDoc(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.docs, path)
}

func newKV2TestSetup(t *testing.T, params map[string]interface{}, credential string) (featsvc.SecretStorageClient, *fakeKV2) {
	t.Helper()

	fake := newFakeKV2()
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)

	if params == nil {
		params = map[string]interface{}{}
	}
	params["url"] = server.URL

	storage := db.SecretStorage{
		ProjectID: 1,
		Name:      "test",
		Type:      db.SecretStorageTypeOpenBao,
		Params:    db.MapStringAnyField(params),
	}

	client, err := featsvc.NewSecretStorageClient(storage, credential)
	require.NoError(t, err)
	return client, fake
}

func TestKV2Health(t *testing.T) {
	client, _ := newKV2TestSetup(t, nil, "good-token")
	require.NoError(t, client.Health())
}

func TestKV2HealthSealed(t *testing.T) {
	client, fake := newKV2TestSetup(t, nil, "good-token")
	fake.mu.Lock()
	fake.sealed = true
	fake.mu.Unlock()

	err := client.Health()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sealed")
}

func TestKV2TokenValidation(t *testing.T) {
	client, _ := newKV2TestSetup(t, nil, "good-token")
	require.NoError(t, client.ValidateCredential())

	client, _ = newKV2TestSetup(t, nil, "bad-token")
	require.Error(t, client.ValidateCredential())
}

func TestKV2AppRoleAuth(t *testing.T) {
	client, fake := newKV2TestSetup(t, map[string]interface{}{"role_id": "role-1"}, "secret-1")
	require.NoError(t, client.Health())
	require.NoError(t, client.ValidateCredential())

	// The AppRole-issued token must be used for data access.
	require.NoError(t, client.Write("ci/approle", map[string]interface{}{"value": "x"}))
	assert.Equal(t, "app-token", fake.lastToken)

	client, _ = newKV2TestSetup(t, map[string]interface{}{"role_id": "role-1"}, "wrong-secret")
	require.Error(t, client.ValidateCredential())
}

func TestKV2WriteReadDelete(t *testing.T) {
	client, _ := newKV2TestSetup(t, nil, "good-token")

	require.NoError(t, client.Write("ci/token", map[string]interface{}{"value": "the-token"}))

	doc, err := client.Read("ci/token")
	require.NoError(t, err)
	assert.Equal(t, "the-token", doc["value"])

	_, err = client.Read("ci/missing")
	assert.ErrorIs(t, err, db.ErrNotFound)

	require.NoError(t, client.Delete("ci/token"))
	// Deleting a missing path is not an error.
	require.NoError(t, client.Delete("ci/token"))
}

func TestKV2ListRecursive(t *testing.T) {
	client, fake := newKV2TestSetup(t, nil, "good-token")
	fake.seed("ci/web/deploy_key", map[string]interface{}{"value": "1"})
	fake.seed("ci/web/db", map[string]interface{}{"value": "2"})
	fake.seed("ci/root", map[string]interface{}{"value": "3"})
	fake.seed("other/thing", map[string]interface{}{"value": "4"})

	leaves, err := client.List("ci")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"ci/web/deploy_key", "ci/web/db", "ci/root"}, leaves)

	leaves, err = client.List("")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"ci/web/deploy_key", "ci/web/db", "ci/root", "other/thing"}, leaves)
}

func TestKV2NamespaceHeader(t *testing.T) {
	client, fake := newKV2TestSetup(t, map[string]interface{}{"namespace": "tenant-a"}, "good-token")
	require.NoError(t, client.Write("ci/ns", map[string]interface{}{"value": "x"}))
	assert.Contains(t, fake.namespaces, "tenant-a")
}

// --- serializer + sync against a real sqlite store ---

type secretStorageTestEnv struct {
	store   *sql.SqlDb
	encSvc  serversvc.AccessKeyEncryptionService
	fake    *fakeKV2
	project db.Project
	storage db.SecretStorage
}

func newSecretStorageTestEnv(t *testing.T) *secretStorageTestEnv {
	t.Helper()

	store := sql.CreateTestStore()
	t.Cleanup(store.Close)

	encSvc := serversvc.NewAccessKeyEncryptionService(store, store, store, store)

	fake := newFakeKV2()
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)

	project, err := store.CreateProject(db.Project{Name: "p"})
	require.NoError(t, err)

	storage, err := store.CreateSecretStorage(db.SecretStorage{
		ProjectID: project.ID,
		Name:      "bao",
		Type:      db.SecretStorageTypeOpenBao,
		Params: db.MapStringAnyField{
			"url":   server.URL,
			"mount": "secret",
		},
	})
	require.NoError(t, err)

	// Storage credential: an access key owned by the storage.
	credentialKey := db.AccessKey{
		Name:      "cred",
		Type:      db.AccessKeyString,
		String:    "good-token",
		ProjectID: &project.ID,
		Owner:     db.AccessKeySecretStorage,
		StorageID: &storage.ID,
	}
	require.NoError(t, encSvc.SerializeSecret(&credentialKey))
	_, err = store.CreateAccessKey(credentialKey)
	require.NoError(t, err)

	return &secretStorageTestEnv{
		store:   store,
		encSvc:  encSvc,
		fake:    fake,
		project: project,
		storage: storage,
	}
}

func vaultSourcePtr() *db.AccessKeySourceStorageType {
	source := db.AccessKeySourceStorageVault
	return &source
}

func TestVaultSerializerRoundtrip(t *testing.T) {
	env := newSecretStorageTestEnv(t)

	deser := featsvc.NewVaultAccessKeyDeserializer(env.store, env.store, env.encSvc)

	path := "ci/deploy"
	key := db.AccessKey{
		Name:              "deploy",
		Type:              db.AccessKeyLoginPassword,
		ProjectID:         &env.project.ID,
		SourceStorageID:   &env.storage.ID,
		SourceStorageKey:  &path,
		SourceStorageType: vaultSourcePtr(),
		LoginPassword:     db.LoginPassword{Login: "user", Password: "pass"},
	}

	require.NoError(t, deser.SerializeSecret(&key))

	doc := env.fake.doc("ci/deploy")
	require.NotNil(t, doc)
	payload, ok := doc["value"].(string)
	require.True(t, ok)
	assert.JSONEq(t, `{"login":"user","password":"pass"}`, payload)

	// Deserialize returns the payload.
	fetched := db.AccessKey{
		Name:              "deploy",
		Type:              db.AccessKeyLoginPassword,
		ProjectID:         &env.project.ID,
		SourceStorageID:   &env.storage.ID,
		SourceStorageKey:  &path,
		SourceStorageType: vaultSourcePtr(),
	}
	got, err := deser.DeserializeSecret(&fetched)
	require.NoError(t, err)
	assert.JSONEq(t, `{"login":"user","password":"pass"}`, got)

	// The full encryption service path unmarshals into the struct.
	require.NoError(t, env.encSvc.DeserializeSecret(&fetched))
	assert.Equal(t, "user", fetched.LoginPassword.Login)
	assert.Equal(t, "pass", fetched.LoginPassword.Password)

	// Delete removes the document and is idempotent.
	require.NoError(t, deser.DeleteSecret(&key))
	require.NoError(t, deser.DeleteSecret(&key))
	assert.Nil(t, env.fake.doc("ci/deploy"))
}

func TestVaultSerializerFieldAddressing(t *testing.T) {
	env := newSecretStorageTestEnv(t)
	env.fake.seed("ci/db", map[string]interface{}{"password": "hunter2", "value": "whole-doc"})

	deser := featsvc.NewVaultAccessKeyDeserializer(env.store, env.store, env.encSvc)

	path := "ci/db#password"
	key := db.AccessKey{
		Name:              "db",
		Type:              db.AccessKeyString,
		ProjectID:         &env.project.ID,
		SourceStorageID:   &env.storage.ID,
		SourceStorageKey:  &path,
		SourceStorageType: vaultSourcePtr(),
	}

	payload, err := deser.DeserializeSecret(&key)
	require.NoError(t, err)
	assert.Equal(t, "hunter2", payload)
}

func TestSyncSecretsStorageLevel(t *testing.T) {
	env := newSecretStorageTestEnv(t)
	env.fake.seed("ci/web/deploy_key", map[string]interface{}{"value": `{"private_key":"KEY"}`})
	env.fake.seed("ci/web/db", map[string]interface{}{"value": `{"login":"u","password":"p"}`})
	env.fake.seed("ci/token", map[string]interface{}{"value": "plain"})

	sync := db.SecretSync{
		ProjectID: env.project.ID,
		StorageID: env.storage.ID,
		Paths: []db.SecretSyncPath{
			{Path: "ci", Prefix: "bao/", Separator: "_"},
		},
	}

	require.NoError(t, featsvc.SyncSecrets(sync, env.store, env.store, env.encSvc))

	keys, err := env.store.GetAccessKeys(env.project.ID, db.GetAccessKeyOptions{
		IgnoreOwner:     true,
		SourceStorageID: &env.storage.ID,
	}, db.RetrieveQueryParams{})
	require.NoError(t, err)
	assert.Len(t, keys, 3)

	byName := map[string]db.AccessKey{}
	for _, key := range keys {
		byName[key.Name] = key
	}
	assert.Equal(t, db.AccessKeySSH, byName["bao/web_deploy_key"].Type)
	assert.Equal(t, db.AccessKeyLoginPassword, byName["bao/web_db"].Type)
	assert.Equal(t, db.AccessKeyString, byName["bao/token"].Type)
	assert.True(t, byName["bao/token"].Synchronized)
	require.NotNil(t, byName["bao/token"].SourceStorageKey)
	assert.Equal(t, "ci/token", *byName["bao/token"].SourceStorageKey)

	// Runtime resolution through the storage reference fills the string key.
	baoToken := byName["bao/token"]
	require.NoError(t, env.encSvc.DeserializeSecret(&baoToken))
	assert.Equal(t, "plain", baoToken.String)

	// Upstream changes: ci/token removed, ci/web/db removed, ci/token2 new.
	env.fake.deleteDoc("ci/token")
	env.fake.deleteDoc("ci/web/db")
	env.fake.seed("ci/token2", map[string]interface{}{"value": "fresh"})

	require.NoError(t, featsvc.SyncSecrets(sync, env.store, env.store, env.encSvc))

	keys, err = env.store.GetAccessKeys(env.project.ID, db.GetAccessKeyOptions{
		IgnoreOwner:     true,
		SourceStorageID: &env.storage.ID,
	}, db.RetrieveQueryParams{})
	require.NoError(t, err)
	assert.Len(t, keys, 2)
	for _, key := range keys {
		assert.NotEqual(t, "bao/token", key.Name, "removed upstream, must be garbage-collected")
		assert.NotEqual(t, "bao/web_db", key.Name, "removed upstream, must be garbage-collected")
	}
}

func TestSyncSecretsEnvironment(t *testing.T) {
	env := newSecretStorageTestEnv(t)
	env.fake.seed("prod/db", map[string]interface{}{"password": "hunter2", "host": "db.local"})

	environmentJSON := "{}"
	environmentENV := "{}"
	environment, err := env.store.CreateEnvironment(db.Environment{
		Name:      "prod",
		ProjectID: env.project.ID,
		JSON:      environmentJSON,
		ENV:       &environmentENV,
	})
	require.NoError(t, err)

	sync := db.SecretSync{
		ProjectID:     env.project.ID,
		StorageID:     env.storage.ID,
		EnvironmentID: &environment.ID,
		Paths: []db.SecretSyncPath{
			{Path: "prod", Prefix: "", Separator: "_"},
		},
	}

	require.NoError(t, featsvc.SyncSecrets(sync, env.store, env.store, env.encSvc))

	keys, err := env.store.GetAccessKeys(env.project.ID, db.GetAccessKeyOptions{
		IgnoreOwner:     true,
		EnvironmentID:   &environment.ID,
		SourceStorageID: &env.storage.ID,
	}, db.RetrieveQueryParams{})
	require.NoError(t, err)
	assert.Len(t, keys, 2)

	byName := map[string]db.AccessKey{}
	for _, key := range keys {
		byName[key.Name] = key
	}
	assert.Contains(t, byName, "var.db_password")
	assert.Contains(t, byName, "var.db_host")

	// Field addressing resolves to the single field value.
	dbPassword := byName["var.db_password"]
	require.NotNil(t, dbPassword.SourceStorageKey)
	assert.Equal(t, "prod/db#password", *dbPassword.SourceStorageKey)

	payloadKey := dbPassword
	require.NoError(t, env.encSvc.DeserializeSecret(&payloadKey))
	assert.Equal(t, "hunter2", payloadKey.String)

	// Deleting the upstream document garbage-collects the variables.
	env.fake.deleteDoc("prod/db")

	require.NoError(t, featsvc.SyncSecrets(sync, env.store, env.store, env.encSvc))

	keys, err = env.store.GetAccessKeys(env.project.ID, db.GetAccessKeyOptions{
		IgnoreOwner:     true,
		EnvironmentID:   &environment.ID,
		SourceStorageID: &env.storage.ID,
	}, db.RetrieveQueryParams{})
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestValidateSecretStorageConnection(t *testing.T) {
	fake := newFakeKV2()
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)

	storage := db.SecretStorage{
		ProjectID: 1,
		Name:      "bao",
		Type:      db.SecretStorageTypeOpenBao,
		Params: db.MapStringAnyField{
			"url":   server.URL,
			"mount": "secret",
		},
	}

	require.NoError(t, featsvc.ValidateSecretStorageConnection(storage, nil, "good-token"))
	require.Error(t, featsvc.ValidateSecretStorageConnection(storage, nil, "bad-token"))

	// env-sourced credential
	t.Setenv("BAO_TEST_TOKEN", "good-token")
	envSource := db.AccessKeySourceStorageEnv
	require.NoError(t, featsvc.ValidateSecretStorageConnection(storage, &envSource, "BAO_TEST_TOKEN"))
}
