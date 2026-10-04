package server

import (
	"fmt"

	"github.com/semaphoreui/semaphore/db"
)

// SecretStorageClient is the SPI for external secret storages. One
// implementation exists today (KV v2, serving both the openbao and vault
// storage types); the AWS Secrets Manager, Azure Key Vault and Devolutions
// Server milestones implement the same interface.
type SecretStorageClient interface {
	// Health reports whether the storage endpoint is reachable and usable
	// (unsealed / initialized for OpenBao and Vault).
	Health() error

	// ValidateCredential proves the storage credential: token self-lookup
	// for token auth, a successful login for AppRole.
	ValidateCredential() error

	// Read returns the KV document at path, or db.ErrNotFound when the
	// path does not exist.
	Read(path string) (map[string]interface{}, error)

	// Write stores the KV document at path.
	Write(path string, data map[string]interface{}) error

	// Delete removes the KV document at path. Missing paths are not an
	// error.
	Delete(path string) error

	// List returns the leaf paths under prefix (directory markers are
	// resolved away; paths are relative to the storage root).
	List(prefix string) ([]string, error)
}

// NewSecretStorageClient builds the client for a storage. credential is the
// resolved storage credential (token, or AppRole secret_id when
// params.role_id is set) — resolution from the credential access key is done
// by the caller (see accessKeyCredential).
func NewSecretStorageClient(storage db.SecretStorage, credential string) (SecretStorageClient, error) {
	switch storage.Type {
	case db.SecretStorageTypeVault, db.SecretStorageTypeOpenBao:
		return newKV2Client(storage, credential)
	default:
		return nil, fmt.Errorf("secret storage type '%s' is not implemented", storage.Type)
	}
}

// ValidateSecretStorageConnection performs the create/update-time "test
// connection": the endpoint must be healthy and the credential must be
// accepted. sourceType/sourceKey describe how the credential is sourced
// (nil = inline value); plain is the inline credential or the env/file
// reference depending on sourceType.
func ValidateSecretStorageConnection(storage db.SecretStorage, sourceType *db.AccessKeySourceStorageType, plain string) error {
	credential, err := resolveStorageCredential(sourceType, plain)
	if err != nil {
		return err
	}

	client, err := NewSecretStorageClient(storage, credential)
	if err != nil {
		return err
	}

	if err = client.Health(); err != nil {
		return err
	}

	return client.ValidateCredential()
}

// resolveStorageCredential mirrors the credential sourcing used by the local
// access-key deserializer: nil source = inline value, env = environment
// variable, file = absolute path (traversal-checked).
func resolveStorageCredential(sourceType *db.AccessKeySourceStorageType, plain string) (string, error) {
	if sourceType == nil {
		return plain, nil
	}

	// env/file resolution needs a key-shaped input; reuse the deserializer
	// logic through a minimal key.
	key := db.AccessKey{
		Type:              db.AccessKeyString,
		SourceStorageType: sourceType,
		SourceStorageKey:  &plain,
	}
	if err := resolveSourceStorageSecret(&key); err != nil {
		return "", err
	}
	return key.String, nil
}

// storageRequiresSecret reports whether a storage needs a stored credential
// at all. Remote storages that authenticate with ambient credentials (for
// example AWS IAM roles) do not.
func storageRequiresSecretImpl(storage db.SecretStorage) bool {
	switch storage.Type {
	case db.SecretStorageTypeAwsSm, db.SecretStorageTypeAzureKv:
		// Ambient-credential storages: no stored credential until their
		// milestones decide otherwise.
		return false
	default:
		return true
	}
}
