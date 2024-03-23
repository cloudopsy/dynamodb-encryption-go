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

// EncryptionMaterials retrieves and stores encryption materials for the given encryption context.
func (p *AwsKmsCryptographicMaterialsProvider) EncryptionMaterials(ctx context.Context, materialName string) (materials.CryptographicMaterials, error) {
	// Generate a new Tink keyset and wrap it
	delegatedKey, wrappedKeyset, err := delegatedkeys.GenerateDataKey(p.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate and wrap data key: %v", err)
	}

	// Assume GenerateSigningKey is modified to return public key as well
	delegatedSigningKey, _, publicKeyBytes, err := delegatedkeys.GenerateSigningKey(p.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate and wrap data key: %v", err)
	}

	// Sign the wrappedKeyset
	signature, err := delegatedSigningKey.Sign(wrappedKeyset)
	if err != nil {
		return nil, fmt.Errorf("failed to sign wrappedKeyset: %v", err)
	}

	// Prepare the material description with encryption context and wrapped keyset
	materialDescription := make(map[string]string)
	for key, value := range p.EncryptionContext {
		materialDescription[key] = value
	}
	materialDescription["ContentEncryptionAlgorithm"] = delegatedKey.Algorithm()
	materialDescription["WrappedKeyset"] = base64.StdEncoding.EncodeToString(wrappedKeyset)
	materialDescription["Signature"] = base64.StdEncoding.EncodeToString(signature)
	materialDescription["PublicKey"] = base64.StdEncoding.EncodeToString(publicKeyBytes)

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

	publicKeyBase64 := materialDescMap["PublicKey"]
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %v", err)
	}

	signatureBase64 := materialDescMap["Signature"]
	signatureBytes, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %v", err)
	}

	valid, err := delegatedkeys.VerifySignature(publicKeyBytes, signatureBytes, encryptedKeyset)
	if err != nil || !valid {
		return nil, fmt.Errorf("failed to verify the wrapped keyset's signature: %v", err)
	}

	delegatedKey, err := delegatedkeys.UnwrapKeyset(encryptedKeyset, p.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt and unwrap data key: %v", err)
	}

	// Construct DecryptionMaterials with the actual delegatedKey
	return materials.NewDecryptionMaterials(materialDescMap, delegatedKey), nil
}

func (p *AwsKmsCryptographicMaterialsProvider) TableName() string {
	return p.MaterialStore.TableName
}
