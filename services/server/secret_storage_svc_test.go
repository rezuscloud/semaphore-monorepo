package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/semaphoreui/semaphore/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- mocks (Fn-injected, project_svc_test.go pattern) --------------------

type mockSecretStorageRepo struct {
	created  []db.SecretStorage
	updated  []db.SecretStorage
	deleted  []int
	storages []db.SecretStorage
}

func (m *mockSecretStorageRepo) GetSecretStorages(projectID int) ([]db.SecretStorage, error) {
	return m.storages, nil
}

func (m *mockSecretStorageRepo) CreateSecretStorage(storage db.SecretStorage) (db.SecretStorage, error) {
	m.created = append(m.created, storage)
	storage.ID = len(m.created)
	return storage, nil
}

func (m *mockSecretStorageRepo) GetSecretStorage(projectID int, storageID int) (db.SecretStorage, error) {
	return db.SecretStorage{ID: storageID, ProjectID: projectID}, nil
}

func (m *mockSecretStorageRepo) UpdateSecretStorage(storage db.SecretStorage) error {
	m.updated = append(m.updated, storage)
	return nil
}

func (m *mockSecretStorageRepo) GetSecretStorageRefs(projectID int, storageID int) (db.ObjectReferrers, error) {
	return db.ObjectReferrers{}, nil
}

func (m *mockSecretStorageRepo) DeleteSecretStorage(projectID int, storageID int) error {
	m.deleted = append(m.deleted, storageID)
	return nil
}

type mockAccessKeySvc struct {
	created []db.AccessKey
	updated []db.AccessKey
	deleted []int
	getAll  []db.AccessKey
}

func (m *mockAccessKeySvc) Update(key db.AccessKey) error {
	m.updated = append(m.updated, key)
	return nil
}

func (m *mockAccessKeySvc) Create(key db.AccessKey) (db.AccessKey, error) {
	m.created = append(m.created, key)
	return key, nil
}

func (m *mockAccessKeySvc) GetAll(int, db.GetAccessKeyOptions, db.RetrieveQueryParams) ([]db.AccessKey, error) {
	return m.getAll, nil
}

func (m *mockAccessKeySvc) Delete(_ int, keyID int) error {
	m.deleted = append(m.deleted, keyID)
	return nil
}

// --- fake OpenBao endpoint (health + token lookup-self) ------------------

func newFakeBaoServer(t *testing.T, validToken string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/sys/health":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"initialized":true,"sealed":false}`))
		case "/v1/auth/token/lookup-self":
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if token != validToken {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"errors":["bad token"]}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"id":"test"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func newStorageFor(url string, storageType db.SecretStorageType) db.SecretStorage {
	return db.SecretStorage{
		ProjectID: 1,
		Name:      "bao",
		Type:      storageType,
		Params:    db.MapStringAnyField{"url": url, "mount": "secret"},
	}
}

func newSecretStorageService(repo *mockSecretStorageRepo, keys *mockAccessKeySvc) SecretStorageService {
	return NewSecretStorageService(repo, nil, keys, nil)
}

// --- create --------------------------------------------------------------

func TestSecretStorageServiceCreate_ValidatesConnection(t *testing.T) {
	bao := newFakeBaoServer(t, "good-token")
	repo := &mockSecretStorageRepo{}
	svc := newSecretStorageService(repo, &mockAccessKeySvc{})

	storage := newStorageFor(bao.URL, db.SecretStorageTypeOpenBao)
	storage.Secret = "bad-token"

	_, err := svc.Create(storage)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection failed")
	assert.Empty(t, repo.created, "storage must not be persisted on failed validation")
}

func TestSecretStorageServiceCreate_PersistsStorageAndCredential(t *testing.T) {
	bao := newFakeBaoServer(t, "good-token")
	repo := &mockSecretStorageRepo{}
	keys := &mockAccessKeySvc{}
	svc := newSecretStorageService(repo, keys)

	storage := newStorageFor(bao.URL, db.SecretStorageTypeOpenBao)
	storage.Secret = "good-token"

	created, err := svc.Create(storage)
	require.NoError(t, err)
	assert.Equal(t, storage.Name, created.Name)
	require.Len(t, repo.created, 1)
	require.Len(t, keys.created, 1)

	credential := keys.created[0]
	assert.Equal(t, db.AccessKeySecretStorage, credential.Owner)
	require.NotNil(t, credential.StorageID)
	assert.Equal(t, created.ID, *credential.StorageID)
	assert.Equal(t, "good-token", credential.String)
	assert.Nil(t, credential.SourceStorageType, "inline secret must not carry a source reference")
}

func TestSecretStorageServiceCreate_EnvSourcedCredential(t *testing.T) {
	bao := newFakeBaoServer(t, "good-token")
	t.Setenv("BAO_TEST_TOKEN", "good-token")
	repo := &mockSecretStorageRepo{}
	keys := &mockAccessKeySvc{}
	svc := newSecretStorageService(repo, keys)

	envSource := db.AccessKeySourceStorageEnv
	storage := newStorageFor(bao.URL, db.SecretStorageTypeVault)
	storage.Secret = "BAO_TEST_TOKEN"
	storage.SourceStorageType = &envSource

	_, err := svc.Create(storage)
	require.NoError(t, err)

	require.Len(t, keys.created, 1)
	credential := keys.created[0]
	require.NotNil(t, credential.SourceStorageType)
	assert.Equal(t, db.AccessKeySourceStorageEnv, *credential.SourceStorageType)
	require.NotNil(t, credential.SourceStorageKey)
	assert.Equal(t, "BAO_TEST_TOKEN", *credential.SourceStorageKey)
}

func TestSecretStorageServiceCreate_RequiresSecret(t *testing.T) {
	repo := &mockSecretStorageRepo{}
	svc := newSecretStorageService(repo, &mockAccessKeySvc{})

	storage := newStorageFor("http://unreachable.invalid", db.SecretStorageTypeOpenBao)
	storage.Secret = ""

	_, err := svc.Create(storage)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret must be set")
}

// --- update --------------------------------------------------------------

func TestSecretStorageServiceUpdate_ValidatesNewCredential(t *testing.T) {
	bao := newFakeBaoServer(t, "good-token")
	repo := &mockSecretStorageRepo{}
	svc := newSecretStorageService(repo, &mockAccessKeySvc{})

	storage := newStorageFor(bao.URL, db.SecretStorageTypeOpenBao)
	storage.ID = 7
	storage.Secret = "bad-token"

	err := svc.Update(storage)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection failed")
	assert.Empty(t, repo.updated, "storage must not be updated on failed validation")
}

func TestSecretStorageServiceUpdate_SkipsValidationWithoutNewSecret(t *testing.T) {
	// No server involved: if validation ran, the unreachable URL would fail.
	repo := &mockSecretStorageRepo{}
	keys := &mockAccessKeySvc{getAll: []db.AccessKey{{ID: 3, Owner: db.AccessKeySecretStorage}}}
	svc := newSecretStorageService(repo, keys)

	storage := newStorageFor("http://unreachable.invalid", db.SecretStorageTypeOpenBao)
	storage.ID = 7
	storage.Secret = ""

	err := svc.Update(storage)
	require.NoError(t, err)
	require.Len(t, repo.updated, 1, "update must proceed without revalidation")
}

func TestSecretStorageServiceUpdate_RemovesCredentialsOnAmbientAuth(t *testing.T) {
	repo := &mockSecretStorageRepo{}
	credentialID := 5
	keys := &mockAccessKeySvc{getAll: []db.AccessKey{{ID: credentialID, Owner: db.AccessKeySecretStorage}}}
	svc := newSecretStorageService(repo, keys)

	// aws_sm authenticates with ambient credentials (no stored secret).
	storage := newStorageFor("", db.SecretStorageTypeAwsSm)
	storage.ID = 7

	err := svc.Update(storage)
	require.NoError(t, err)
	require.Len(t, repo.updated, 1)
	assert.Equal(t, []int{credentialID}, keys.deleted, "stored credentials must be removed")
}

// --- list ----------------------------------------------------------------

func TestSecretStorageServiceGetSecretStorages_DelegatesToRepo(t *testing.T) {
	repo := &mockSecretStorageRepo{
		storages: []db.SecretStorage{{ID: 1, Name: "bao"}, {ID: 2, Name: "vault"}},
	}
	svc := newSecretStorageService(repo, &mockAccessKeySvc{})

	storages, err := svc.GetSecretStorages(1)
	require.NoError(t, err)
	assert.Len(t, storages, 2, "list endpoint must return repo data, not the old empty stub")
}
