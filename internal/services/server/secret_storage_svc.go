package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/semaphoreui/semaphore/db"
)

func GetSecretStorages(repo db.SecretStorageRepository, projectID int) (storages []db.SecretStorage, err error) {
	return repo.GetSecretStorages(projectID)
}

func StorageRequiresSecret(storage db.SecretStorage) bool {
	return storageRequiresSecretImpl(storage)
}

// SyncSecrets imports secrets from an external storage. A storage-level sync
// (EnvironmentID == nil) imports one access key per KV document; an
// env-scoped sync imports one environment variable per KV document field
// (owner "var.", name <prefix><path><separator><field>, referenced as
// "path#field").
//
// Synced keys hold references only (SourceStorageID + SourceStorageKey) —
// values are fetched at task runtime. Keys that disappeared from the
// storage are removed (garbage collection).
func SyncSecrets(
	sync db.SecretSync,
	storageRepo db.SecretStorageRepository,
	accessKeyRepo db.AccessKeyManager,
	decryptor DvlsStorageTokenDeserializer,
) error {
	storage, err := storageRepo.GetSecretStorage(sync.ProjectID, sync.StorageID)
	if err != nil {
		return err
	}

	credential, err := accessKeyCredential(accessKeyRepo, decryptor, storage)
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

	if sync.EnvironmentID == nil {
		return syncAccessKeys(sync, client, accessKeyRepo)
	}
	return syncEnvironmentSecrets(sync, client, accessKeyRepo)
}

// listSyncDocuments lists the leaf documents under every sync path.
func listSyncDocuments(client SecretStorageClient, paths []db.SecretSyncPath) (map[string][]string, error) {
	listing := make(map[string][]string, len(paths))
	for _, syncPath := range paths {
		leaves, err := client.List(syncPath.Path)
		if err != nil {
			return nil, fmt.Errorf("listing %s failed: %w", syncPath.Path, err)
		}
		listing[syncPath.Path] = leaves
	}
	return listing, nil
}

func syncPathSeparator(syncPath db.SecretSyncPath) string {
	if syncPath.Separator == "" {
		return "_"
	}
	return syncPath.Separator
}

// relativeName builds the imported object name for a leaf path: the
// segments below the sync path, joined with the path separator, prefixed.
func relativeName(syncPath db.SecretSyncPath, leaf string) string {
	root := strings.Trim(syncPath.Path, "/")
	rel := strings.Trim(strings.TrimPrefix(strings.Trim(leaf, "/"), root), "/")
	segments := strings.Split(rel, "/")
	filtered := make([]string, 0, len(segments))
	for _, segment := range segments {
		if segment != "" {
			filtered = append(filtered, segment)
		}
	}
	return syncPath.Prefix + strings.Join(filtered, syncPathSeparator(syncPath))
}

func inferAccessKeyType(payload string) (db.AccessKeyType, error) {
	trimmed := strings.TrimSpace(payload)
	if !strings.HasPrefix(trimmed, "{") {
		return db.AccessKeyString, nil
	}

	var probe map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &probe); err != nil {
		// Not a JSON object after all — treat as a plain string.
		return db.AccessKeyString, nil
	}

	if _, ok := probe["private_key"]; ok {
		return db.AccessKeySSH, nil
	}
	if _, ok := probe["password"]; ok {
		return db.AccessKeyLoginPassword, nil
	}
	if _, ok := probe["login"]; ok {
		return db.AccessKeyLoginPassword, nil
	}
	return db.AccessKeyString, nil
}

// syncAccessKeys imports KV documents as shared access keys.
func syncAccessKeys(
	sync db.SecretSync,
	client SecretStorageClient,
	accessKeyRepo db.AccessKeyManager,
) error {
	listing, err := listSyncDocuments(client, sync.Paths)
	if err != nil {
		return err
	}

	existing, err := accessKeyRepo.GetAccessKeys(sync.ProjectID, db.GetAccessKeyOptions{
		IgnoreOwner:     true,
		SourceStorageID: &sync.StorageID,
	}, db.RetrieveQueryParams{})
	if err != nil {
		return err
	}

	byPath := make(map[string]*db.AccessKey, len(existing))
	for i := range existing {
		if existing[i].SourceStorageKey != nil {
			byPath[*existing[i].SourceStorageKey] = &existing[i]
		}
	}

	vaultSource := db.AccessKeySourceStorageVault
	seen := make(map[string]bool)

	for _, syncPath := range sync.Paths {
		for _, leaf := range listing[syncPath.Path] {
			doc, err := client.Read(leaf)
			if err != nil {
				return fmt.Errorf("reading %s failed: %w", leaf, err)
			}

			payload, err := kv2DocumentValue(doc)
			if err != nil {
				return fmt.Errorf("importing %s failed: %w", leaf, err)
			}

			keyType, err := inferAccessKeyType(payload)
			if err != nil {
				return err
			}

			name := relativeName(syncPath, leaf)
			path := leaf
			seen[path] = true

			if existingKey, ok := byPath[path]; ok {
				if existingKey.Name != name || existingKey.Type != keyType {
					existingKey.Name = name
					existingKey.Type = keyType
					if err = accessKeyRepo.UpdateAccessKey(*existingKey); err != nil {
						return err
					}
				}
				continue
			}

			_, err = accessKeyRepo.CreateAccessKey(db.AccessKey{
				Name:              name,
				Type:              keyType,
				ProjectID:         &sync.ProjectID,
				SourceStorageID:   &sync.StorageID,
				SourceStorageKey:  &path,
				SourceStorageType: &vaultSource,
				Synchronized:      true,
			})
			if err != nil {
				return err
			}
		}
	}

	// Garbage-collect synced keys whose documents disappeared.
	for i := range existing {
		key := existing[i]
		if !key.Synchronized || key.SourceStorageKey == nil {
			continue
		}
		if seen[*key.SourceStorageKey] {
			continue
		}
		// Only GC keys below one of the sync paths — a manually created
		// reference outside the synced prefixes is the user's own.
		underSyncPath := false
		for _, syncPath := range sync.Paths {
			if strings.HasPrefix(*key.SourceStorageKey+"/", strings.Trim(syncPath.Path, "/")+"/") {
				underSyncPath = true
				break
			}
		}
		if underSyncPath {
			if err = accessKeyRepo.DeleteAccessKey(sync.ProjectID, key.ID); err != nil {
				return err
			}
		}
	}

	return nil
}

// syncEnvironmentSecrets imports every field of the KV documents under the
// sync paths as environment variables (access keys owned by the
// environment, owner "var.").
func syncEnvironmentSecrets(
	sync db.SecretSync,
	client SecretStorageClient,
	accessKeyRepo db.AccessKeyManager,
) error {
	listing, err := listSyncDocuments(client, sync.Paths)
	if err != nil {
		return err
	}

	existing, err := accessKeyRepo.GetAccessKeys(sync.ProjectID, db.GetAccessKeyOptions{
		IgnoreOwner:     true,
		EnvironmentID:   sync.EnvironmentID,
		SourceStorageID: &sync.StorageID,
	}, db.RetrieveQueryParams{})
	if err != nil {
		return err
	}

	byName := make(map[string]*db.AccessKey, len(existing))
	for i := range existing {
		byName[existing[i].Name] = &existing[i]
	}

	vaultSource := db.AccessKeySourceStorageVault
	seen := make(map[string]bool)

	for _, syncPath := range sync.Paths {
		for _, leaf := range listing[syncPath.Path] {
			doc, err := client.Read(leaf)
			if err != nil {
				return fmt.Errorf("reading %s failed: %w", leaf, err)
			}

			docBase := relativeName(syncPath, leaf)

			for field := range doc {
				name := string(db.EnvironmentSecretVar) + "." + docBase + syncPathSeparator(syncPath) + field
				sourceKey := leaf + "#" + field
				seen[name] = true

				if existingKey, ok := byName[name]; ok {
					if existingKey.SourceStorageKey == nil || *existingKey.SourceStorageKey != sourceKey {
						path := sourceKey
						existingKey.SourceStorageKey = &path
						if err = accessKeyRepo.UpdateAccessKey(*existingKey); err != nil {
							return err
						}
					}
					continue
				}

				_, err = accessKeyRepo.CreateAccessKey(db.AccessKey{
					Name:              name,
					Type:              db.AccessKeyString,
					ProjectID:         &sync.ProjectID,
					EnvironmentID:     sync.EnvironmentID,
					Owner:             db.AccessKeyVariable,
					SourceStorageID:   &sync.StorageID,
					SourceStorageKey:  &sourceKey,
					SourceStorageType: &vaultSource,
					Synchronized:      true,
				})
				if err != nil {
					return err
				}
			}
		}
	}

	// Garbage-collect synced variables that no longer exist upstream.
	for i := range existing {
		key := existing[i]
		if !key.Synchronized {
			continue
		}
		if !seen[key.Name] {
			if err = accessKeyRepo.DeleteAccessKey(sync.ProjectID, key.ID); err != nil {
				return err
			}
		}
	}

	return nil
}

// resolveSourceStorageSecret fills key.String from an env / file source
// reference. It mirrors the community local deserializer's rules; the
// internal package cannot import it (import cycle), so the small surface
// is duplicated here.
func resolveSourceStorageSecret(key *db.AccessKey) error {
	if key.SourceStorageType == nil || key.SourceStorageKey == nil {
		return fmt.Errorf("source storage reference is incomplete")
	}

	switch *key.SourceStorageType {
	case db.AccessKeySourceStorageEnv:
		key.String = os.Getenv(*key.SourceStorageKey)
		return nil
	case db.AccessKeySourceStorageFile:
		filePath := filepath.Clean(*key.SourceStorageKey)
		if !filepath.IsAbs(filePath) {
			return fmt.Errorf("file path must be absolute")
		}
		content, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}
		key.String = strings.TrimSpace(string(content))
		return nil
	default:
		return fmt.Errorf("unsupported source storage type '%s'", *key.SourceStorageType)
	}
}
