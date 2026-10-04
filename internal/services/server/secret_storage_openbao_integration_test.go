//go:build integration_openbao

package server_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/db/sql"
	featsvc "github.com/semaphoreui/semaphore/internal/services/server"
	serversvc "github.com/semaphoreui/semaphore/services/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOpenBaoEndToEnd runs the whole secret-storage flow against a real
// OpenBao dev server (CI job integrate-openbao). Skipped unless
// OPENBAO_ADDR / OPENBAO_TOKEN are set.
func TestOpenBaoEndToEnd(t *testing.T) {
	addr := os.Getenv("OPENBAO_ADDR")
	token := os.Getenv("OPENBAO_TOKEN")
	if addr == "" || token == "" {
		t.Skip("OPENBAO_ADDR / OPENBAO_TOKEN not set — skipping live OpenBao test")
	}

	// --- client level -------------------------------------------------
	client, err := featsvc.NewSecretStorageClient(db.SecretStorage{
		ProjectID: 1,
		Name:      "bao",
		Type:      db.SecretStorageTypeOpenBao,
		Params: db.MapStringAnyField{
			"url":   addr,
			"mount": "secret",
		},
	}, token)
	require.NoError(t, err)

	require.NoError(t, client.Health(), "dev server must be healthy")
	require.NoError(t, client.ValidateCredential(), "root token must validate")

	require.NoError(t, client.Write("itest/ci/web/db", map[string]interface{}{"value": `{"login":"u","password":"p"}`}))
	require.NoError(t, client.Write("itest/ci/token", map[string]interface{}{"value": "plain"}))

	doc, err := client.Read("itest/ci/token")
	require.NoError(t, err)
	assert.Equal(t, "plain", doc["value"])

	leaves, err := client.List("itest")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"itest/ci/web/db", "itest/ci/token"}, leaves)

	// --- full stack: storage + credential + serializer + sync --------
	store := sql.CreateTestStore()
	t.Cleanup(store.Close)

	encSvc := serversvc.NewAccessKeyEncryptionService(store, store, store, store)

	project, err := store.CreateProject(db.Project{Name: "itest"})
	require.NoError(t, err)

	storage, err := store.CreateSecretStorage(db.SecretStorage{
		ProjectID: project.ID,
		Name:      "bao",
		Type:      db.SecretStorageTypeOpenBao,
		Params: db.MapStringAnyField{
			"url":   addr,
			"mount": "secret",
		},
	})
	require.NoError(t, err)

	credentialKey := db.AccessKey{
		Name:      "cred",
		Type:      db.AccessKeyString,
		String:    token,
		ProjectID: &project.ID,
		Owner:     db.AccessKeySecretStorage,
		StorageID: &storage.ID,
	}
	require.NoError(t, encSvc.SerializeSecret(&credentialKey))
	_, err = store.CreateAccessKey(credentialKey)
	require.NoError(t, err)

	// storage-level sync imports the seeded documents as access keys
	sync := db.SecretSync{
		ProjectID: project.ID,
		StorageID: storage.ID,
		Paths:     []db.SecretSyncPath{{Path: "itest", Prefix: "", Separator: "_"}},
	}
	require.NoError(t, featsvc.SyncSecrets(sync, store, store, encSvc))

	keys, err := store.GetAccessKeys(project.ID, db.GetAccessKeyOptions{
		IgnoreOwner:     true,
		SourceStorageID: &storage.ID,
	}, db.RetrieveQueryParams{})
	require.NoError(t, err)
	assert.Len(t, keys, 2)

	byName := map[string]db.AccessKey{}
	for _, key := range keys {
		byName[key.Name] = key
	}
	assert.Equal(t, db.AccessKeyLoginPassword, byName["ci_web_db"].Type)

	// runtime resolution fetches from OpenBao
	dbKey := byName["ci_web_db"]
	require.NoError(t, encSvc.DeserializeSecret(&dbKey))
	assert.Equal(t, "u", dbKey.LoginPassword.Login)
	assert.Equal(t, "p", dbKey.LoginPassword.Password)

	// env-scoped sync: fields of a document become environment variables
	envJSON, envENV := "{}", "{}"
	environment, err := store.CreateEnvironment(db.Environment{
		Name:      "prod",
		ProjectID: project.ID,
		JSON:      envJSON,
		ENV:       &envENV,
	})
	require.NoError(t, err)

	require.NoError(t, client.Write("itest/prod/db", map[string]interface{}{"password": "hunter2", "host": "db.local"}))

	envSync := db.SecretSync{
		ProjectID:     project.ID,
		StorageID:     storage.ID,
		EnvironmentID: &environment.ID,
		Paths:         []db.SecretSyncPath{{Path: "itest/prod", Prefix: "", Separator: "_"}},
	}
	require.NoError(t, featsvc.SyncSecrets(envSync, store, store, encSvc))

	envKeys, err := store.GetAccessKeys(project.ID, db.GetAccessKeyOptions{
		IgnoreOwner:     true,
		EnvironmentID:   &environment.ID,
		SourceStorageID: &storage.ID,
	}, db.RetrieveQueryParams{})
	require.NoError(t, err)
	assert.Len(t, envKeys, 2)

	for _, key := range envKeys {
		resolved := key
		require.NoError(t, encSvc.DeserializeSecret(&resolved), fmt.Sprintf("resolving %s", key.Name))
		switch key.Name {
		case "var.db_password":
			assert.Equal(t, "hunter2", resolved.String)
		case "var.db_host":
			assert.Equal(t, "db.local", resolved.String)
		default:
			t.Fatalf("unexpected variable name: %s", key.Name)
		}
	}

	// cleanup of the storage-prefixed secrets
	require.NoError(t, client.Delete("itest/ci/web/db"))
	require.NoError(t, client.Delete("itest/ci/token"))
	require.NoError(t, client.Delete("itest/prod/db"))
}
