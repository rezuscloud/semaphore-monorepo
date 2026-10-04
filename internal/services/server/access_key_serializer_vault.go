package server

import (
	"encoding/json"
	"fmt"

	"github.com/semaphoreui/semaphore/db"
)

// VaultStorageTokenDeserializer resolves the storage credential access key
// (env / file / locally encrypted) into its plain value.
type VaultStorageTokenDeserializer interface {
	DeserializeSecret(key *db.AccessKey) error
}

// VaultAccessKeyDeserializer stores access keys as references into an
// OpenBao / HashiCorp Vault KV v2 secret storage: the semaphore database
// keeps only the storage id + path (SourceStorageKey), the payload is
// fetched at task runtime and written back on save.
//
// Payload contract: the KV document holds the access-key secret under the
// "value" field — plain string for string keys, the JSON encoding of
// SshKey / LoginPassword for ssh and login_password keys.
type VaultAccessKeyDeserializer struct {
	accessKeyRepo     db.AccessKeyManager
	secretStorageRepo db.SecretStorageRepository
	tokenDeserializer VaultStorageTokenDeserializer
}

func NewVaultAccessKeyDeserializer(
	accessKeyRepo db.AccessKeyManager,
	secretStorageRepo db.SecretStorageRepository,
	tokenDeserializer VaultStorageTokenDeserializer,
) *VaultAccessKeyDeserializer {
	return &VaultAccessKeyDeserializer{
		accessKeyRepo:     accessKeyRepo,
		secretStorageRepo: secretStorageRepo,
		tokenDeserializer: tokenDeserializer,
	}
}

// accessKeyCredential resolves the storage credential through the credential
// access key (owner "vault", StorageID = storage id).
func accessKeyCredential(
	accessKeyRepo db.AccessKeyManager,
	tokenDeserializer VaultStorageTokenDeserializer,
	storage db.SecretStorage,
) (string, error) {
	if storage.ProjectID == 0 {
		return "", fmt.Errorf("storage has no project")
	}

	keys, err := accessKeyRepo.GetAccessKeys(storage.ProjectID, db.GetAccessKeyOptions{
		Owner:     db.AccessKeySecretStorage,
		StorageID: &storage.ID,
	}, db.RetrieveQueryParams{})
	if err != nil {
		return "", err
	}

	if len(keys) == 0 {
		// Storages that do not require a credential (ambient auth).
		return "", nil
	}

	if err = tokenDeserializer.DeserializeSecret(&keys[0]); err != nil {
		return "", err
	}

	return keys[0].String, nil
}

func (d *VaultAccessKeyDeserializer) client(key *db.AccessKey) (SecretStorageClient, error) {
	if key.ProjectID == nil || key.SourceStorageID == nil {
		return nil, fmt.Errorf("access key has no secret storage reference")
	}

	storage, err := d.secretStorageRepo.GetSecretStorage(*key.ProjectID, *key.SourceStorageID)
	if err != nil {
		return nil, err
	}

	credential, err := accessKeyCredential(d.accessKeyRepo, d.tokenDeserializer, storage)
	if err != nil {
		return nil, err
	}

	return NewSecretStorageClient(storage, credential)
}

func (d *VaultAccessKeyDeserializer) sourcePath(key *db.AccessKey) (string, error) {
	if key.SourceStorageKey == nil || *key.SourceStorageKey == "" {
		return "", fmt.Errorf("access key '%s' has no secret storage path", key.Name)
	}
	return *key.SourceStorageKey, nil
}

// marshalPayload encodes the key value exactly like the local deserializer
// does (JSON for structured keys, plain string for string keys).
func marshalPayload(key *db.AccessKey) (string, error) {
	switch key.Type {
	case db.AccessKeyString:
		return key.String, nil
	case db.AccessKeySSH:
		encoded, err := json.Marshal(key.SshKey)
		return string(encoded), err
	case db.AccessKeyLoginPassword:
		encoded, err := json.Marshal(key.LoginPassword)
		return string(encoded), err
	case db.AccessKeyNone:
		return "", nil
	default:
		return "", fmt.Errorf("invalid access key type '%s'", key.Type)
	}
}

// SerializeSecret implements AccessKeyDeserializer: pushes the key value
// into the KV storage.
func (d *VaultAccessKeyDeserializer) SerializeSecret(key *db.AccessKey) error {
	client, err := d.client(key)
	if err != nil {
		return err
	}

	path, err := d.sourcePath(key)
	if err != nil {
		return err
	}

	payload, err := marshalPayload(key)
	if err != nil {
		return err
	}

	return client.Write(path, map[string]interface{}{
		kv2ValueField: payload,
	})
}

// DeserializeSecret implements AccessKeyDeserializer: fetches the key value
// from the KV storage. SourceStorageKey may address a whole document
// ("value" field) or a single field ("path#field").
func (d *VaultAccessKeyDeserializer) DeserializeSecret(key *db.AccessKey) (res string, err error) {
	client, err := d.client(key)
	if err != nil {
		return
	}

	sourceKey, err := d.sourcePath(key)
	if err != nil {
		return
	}

	docPath, field := splitFieldAddress(sourceKey)

	doc, err := client.Read(docPath)
	if err != nil {
		return
	}

	if field == "" {
		return kv2DocumentValue(doc)
	}

	raw, ok := doc[field]
	if !ok {
		return "", fmt.Errorf("secret document has no '%s' field", field)
	}
	if s, ok := raw.(string); ok {
		return s, nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("secret field '%s' is not serializable", field)
	}
	return string(encoded), nil
}

// DeleteSecret implements AccessKeyDeserializer: removes the KV document.
func (d *VaultAccessKeyDeserializer) DeleteSecret(key *db.AccessKey) error {
	client, err := d.client(key)
	if err != nil {
		return err
	}

	path, err := d.sourcePath(key)
	if err != nil {
		return err
	}

	return client.Delete(path)
}
