package projects

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/semaphoreui/semaphore/api/helpers"
	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/db/sql"
	featServer "github.com/semaphoreui/semaphore/internal/services/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockSecretStorageService struct {
	created  []db.SecretStorage
	updated  []db.SecretStorage
	deleted  []int
	synced   []int
	storages []db.SecretStorage
}

func (m *mockSecretStorageService) GetSecretStorage(projectID int, storageID int) (db.SecretStorage, error) {
	return db.SecretStorage{ID: storageID, ProjectID: projectID}, nil
}

func (m *mockSecretStorageService) Update(storage db.SecretStorage) error {
	m.updated = append(m.updated, storage)
	return nil
}

func (m *mockSecretStorageService) Delete(projectID int, storageID int) error {
	m.deleted = append(m.deleted, storageID)
	return nil
}

func (m *mockSecretStorageService) GetSecretStorages(projectID int) ([]db.SecretStorage, error) {
	return m.storages, nil
}

func (m *mockSecretStorageService) Create(storage db.SecretStorage) (db.SecretStorage, error) {
	m.created = append(m.created, storage)
	storage.ID = 1
	return storage, nil
}

func (m *mockSecretStorageService) SyncSecrets(sync db.SecretSync) error {
	m.synced = append(m.synced, sync.StorageID)
	return nil
}

func newSecretStorageController() (*SecretStorageController, *mockSecretStorageService) {
	svc := &mockSecretStorageService{}
	return NewSecretStorageController(nil, svc), svc
}

func newProjectRequest(method, url, body string) (*http.Request, *httptest.ResponseRecorder) {
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, url, reader)
	req = helpers.SetContextValue(req, "project", db.Project{ID: 1})
	return req, httptest.NewRecorder()
}

// newEventLoggedRequest seeds the contexts the event log needs on success
// paths (store, user, log writer) — the runners_test.go pattern.
func newEventLoggedRequest(req *http.Request, store *sql.SqlDb) *http.Request {
	req = helpers.SetContextValue(req, "store", store)
	req = helpers.SetContextValue(req, "user", &db.User{ID: 1, Username: "tester"})
	req = helpers.SetContextValue(req, "log_writer", featServer.NewLogWriteService())
	return req
}

func newStorageRequest(method, url, body string, oldStorage db.SecretStorage) (*http.Request, *httptest.ResponseRecorder) {
	req, w := newProjectRequest(method, url, body)
	req = helpers.SetContextValue(req, "secretStorage", oldStorage)
	return req, w
}

func TestAddSecretStorage_RejectsCrossProjectMove(t *testing.T) {
	ctrl, svc := newSecretStorageController()

	body := `{"name":"bao","type":"openbao","project_id":999}`
	req, w := newProjectRequest(http.MethodPost, "/api/project/1/secret_storages", body)

	ctrl.Add(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "must be the same")
	assert.Empty(t, svc.created, "service must not be touched on rejection")
}

func TestAddSecretStorage_CreatesThroughService(t *testing.T) {
	ctrl, svc := newSecretStorageController()
	store := sql.CreateTestStore()
	t.Cleanup(store.Close)

	body := `{"name":"bao","type":"openbao","project_id":1,"params":{"url":"http://x"}}`
	req, w := newProjectRequest(http.MethodPost, "/api/project/1/secret_storages", body)
	req = newEventLoggedRequest(req, store)

	ctrl.Add(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	require.Len(t, svc.created, 1)
	assert.Equal(t, "bao", svc.created[0].Name)
}

func TestGetSecretStorages_ReturnsServiceList(t *testing.T) {
	ctrl, svc := newSecretStorageController()
	svc.storages = []db.SecretStorage{{ID: 1, Name: "bao"}, {ID: 2, Name: "vault"}}

	req, w := newProjectRequest(http.MethodGet, "/api/project/1/secret_storages", "")

	ctrl.GetSecretStorages(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"bao"`)
	assert.Contains(t, w.Body.String(), `"vault"`)
}

func TestUpdateSecretStorage_RejectsBodyIDMismatch(t *testing.T) {
	ctrl, svc := newSecretStorageController()

	oldStorage := db.SecretStorage{ID: 7, ProjectID: 1}
	body := `{"id":42,"name":"bao","project_id":1}`
	req, w := newStorageRequest(http.MethodPut, "/api/project/1/secret_storages/7", body, oldStorage)

	ctrl.Update(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "must be the same")
	assert.Empty(t, svc.updated, "service must not be touched on rejection")
}

func TestUpdateSecretStorage_RejectsCrossProjectMove(t *testing.T) {
	ctrl, svc := newSecretStorageController()

	oldStorage := db.SecretStorage{ID: 7, ProjectID: 1}
	body := `{"id":7,"name":"bao","project_id":999}`
	req, w := newStorageRequest(http.MethodPut, "/api/project/1/secret_storages/7", body, oldStorage)

	ctrl.Update(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "other project")
	assert.Empty(t, svc.updated, "service must not be touched on rejection")
}

func TestUpdateSecretStorage_UpdatesThroughService(t *testing.T) {
	ctrl, svc := newSecretStorageController()
	store := sql.CreateTestStore()
	t.Cleanup(store.Close)

	oldStorage := db.SecretStorage{ID: 7, ProjectID: 1}
	body := `{"id":7,"name":"bao2","project_id":1}`
	req, w := newStorageRequest(http.MethodPut, "/api/project/1/secret_storages/7", body, oldStorage)
	req = newEventLoggedRequest(req, store)

	ctrl.Update(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	require.Len(t, svc.updated, 1)
	assert.Equal(t, "bao2", svc.updated[0].Name)
}

func TestSyncSecretStorage_RejectsBodyIDMismatch(t *testing.T) {
	ctrl, svc := newSecretStorageController()

	oldStorage := db.SecretStorage{ID: 7, ProjectID: 1}
	body := `{"id":42,"project_id":1}`
	req, w := newStorageRequest(http.MethodPost, "/api/project/1/secret_storages/7/sync", body, oldStorage)

	ctrl.SyncSecrets(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Empty(t, svc.synced, "sync must not run on rejection")
}
