package provider

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/cloudopsy/dynamodb-encryption-go/pkg/delegatedkeys"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/materials"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/provider/store"
)

// AwsKmsCryptographicMaterialsProvider uses AWS KMS for key management and Tink for cryptographic operations.
type AwsKmsCryptographicMaterialsProvider struct {
	KeyID             string
	EncryptionContext map[string]string
	DelegatedKey      *delegatedkeys.TinkDelegatedKey
	MaterialStore     *store.MetaStore
}

// NewAwsKmsCryptographicMaterialsProvider initializes a provider with the specified AWS KMS key ID, encryption context, and material store.
func NewAwsKmsCryptographicMaterialsProvider(keyID string, encryptionContext map[string]string, materialStore *store.MetaStore) (CryptographicMaterialsProvider, error) {

	return &AwsKmsCryptographicMaterialsProvider{
		KeyID:             keyID,
		EncryptionContext: encryptionContext,
		MaterialStore:     materialStore,
	}, nil
}

// GenerateDataKey generates a new data key using AWS KMS and wraps the Tink keyset.
func (p *AwsKmsCryptographicMaterialsProvider) GenerateDataKey() (*delegatedkeys.TinkDelegatedKey, []byte, error) {
	delegatedKey, wrappedKeyset, err := delegatedkeys.GenerateDataKey(p.KeyID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate data key: %v", err)
	}

	return delegatedKey, wrappedKeyset, nil
}

// DecryptDataKey unwraps the Tink keyset using AWS KMS.
func (p *AwsKmsCryptographicMaterialsProvider) DecryptDataKey(encryptedKeyset []byte) (*delegatedkeys.TinkDelegatedKey, error) {
	return delegatedkeys.UnwrapKeyset(encryptedKeyset, p.KeyID)
}

// EncryptionMaterials retrieves and stores encryption materials for the given encryption context.
func (p *AwsKmsCryptographicMaterialsProvider) EncryptionMaterials(ctx context.Context, materialName string) (materials.CryptographicMaterials, error) {
	// Generate a new Tink keyset and wrap it
	delegatedKey, wrappedKeyset, err := p.GenerateDataKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate and wrap data key: %v", err)
	}

	// Prepare the material description with encryption context and wrapped keyset
	materialDescription := make(map[string]string)
	for key, value := range p.EncryptionContext {
		materialDescription[key] = value
	}
	materialDescription["ContentEncryptionAlgorithm"] = delegatedKey.Algorithm()
	materialDescription["WrappedKeyset"] = base64.StdEncoding.EncodeToString(wrappedKeyset)

	// Create encryption materials with the material description and the encryption key
	encryptionMaterials := materials.NewEncryptionMaterials(materialDescription, delegatedKey, nil)

	// Store the new material in the material store
	if err := p.MaterialStore.StoreNewMaterial(ctx, materialName, encryptionMaterials); err != nil {
		return nil, fmt.Errorf("failed to store encryption material: %v", err)
	}

	return encryptionMaterials, nil
}

func (p *AwsKmsCryptographicMaterialsProvider) DecryptionMaterials(ctx context.Context, materialName string, version int64) (materials.CryptographicMaterials, error) {
	materialDescMap, wrappedKeysetBase64, err := p.MaterialStore.RetrieveMaterial(ctx, materialName, version)
	if err != nil {
		return nil, err
	}

	encryptedKeyset, err := base64.StdEncoding.DecodeString(wrappedKeysetBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted keyset: %v", err)
	}

	delegatedKey, err := p.DecryptDataKey(encryptedKeyset)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt and unwrap data key: %v", err)
	}

	// Construct DecryptionMaterials with the actual delegatedKey
	return materials.NewDecryptionMaterials(materialDescMap, delegatedKey, nil), nil
}

func (p *AwsKmsCryptographicMaterialsProvider) TableName() string {
	return p.MaterialStore.TableName
}
