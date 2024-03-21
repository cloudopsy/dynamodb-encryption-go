package provider

import (
<<<<<<< HEAD
	"fmt"

	"github.com/cloudopsy/dynamodb-encryption-go/pkg/crypto"
)

type CryptographicMaterialsProvider struct {
	cryptoProvider crypto.Crypto
	description    map[string]string
}

const WrappedDataKeyAttrName = "__wrapped_data_key"

func NewCryptographicMaterialsProvider(cryptoProvider *crypto.Crypto, description map[string]string) *CryptographicMaterialsProvider {
	return &CryptographicMaterialsProvider{
		cryptoProvider: *cryptoProvider,
		description:    description,
	}
}

// EncryptionMaterials generates materials needed for encryption, including an encrypted data key.
func (p *CryptographicMaterialsProvider) EncryptionMaterials(context map[string]string) (map[string][]byte, error) {
	_, encryptedDataKey, err := p.cryptoProvider.GenerateDataKey(context)
	if err != nil {
		return nil, fmt.Errorf("failed to generate data key: %v", err)
	}

	materialDescription := map[string][]byte{WrappedDataKeyAttrName: encryptedDataKey}
	for k, v := range p.description {
		materialDescription[k] = []byte(v)
	}

	return materialDescription, nil
}

// DecryptionMaterials prepares the context needed for decryption based on the provided encrypted materials.
func (p *CryptographicMaterialsProvider) DecryptionMaterials(encryptedMaterials map[string][]byte) (map[string]string, error) {
	encryptedDataKey, exists := encryptedMaterials[WrappedDataKeyAttrName]
	if !exists {
		return nil, fmt.Errorf("encrypted data key not found in materials")
	}

	plaintextDataKey, err := p.cryptoProvider.DecryptDataKey(encryptedDataKey, p.description) // Assuming description is used as context here.
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data key: %v", err)
	}

	// Convert plaintextDataKey to a string map if needed, or use it directly depending on your use case.
	// This example assumes the decryption context is similar to the encryption context.
	decryptionContext := make(map[string]string)
	for k, _ := range p.description {
		decryptionContext[k] = string(plaintextDataKey) // Simplified; likely you'll need a more complex handling based on actual context usage.
	}

	return decryptionContext, nil
=======
	"context"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// CryptographicMaterialsProvider is an interface for handling cryptographic materials.
type CryptographicMaterialsProvider interface {
	EncryptionMaterials(ctx context.Context, encryptionContext map[string]types.AttributeValue) (map[string]types.AttributeValue, error)
	DecryptionMaterials(ctx context.Context, encryptionContext map[string]types.AttributeValue) (map[string]types.AttributeValue, error)
	EncryptAttribute(ctx context.Context, attributeName string, attributeValue types.AttributeValue) (types.AttributeValue, error)
	DecryptAttribute(ctx context.Context, attributeName string, encryptedValue types.AttributeValue) (types.AttributeValue, error)
>>>>>>> 8f215692218746a35cf2f8ab7c1b1f091dd09197
}
