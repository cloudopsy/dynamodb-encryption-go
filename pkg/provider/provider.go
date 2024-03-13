package provider

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go/service/dynamodb"
)

// CryptoProvider is an interface for a cryptographic provider
type CryptoProvider interface {
	EncryptAttribute(ctx context.Context, attributeName string, attributeValue *dynamodb.AttributeValue) (*dynamodb.AttributeValue, error)
	DecryptAttribute(ctx context.Context, attributeName string, ciphertext []byte) (*dynamodb.AttributeValue, error)
	EncryptAttributeDeterministically(ctx context.Context, attributeName string, attributeValue *dynamodb.AttributeValue) (*dynamodb.AttributeValue, error)
	DecryptAttributeDeterministically(ctx context.Context, attributeName string, ciphertext []byte) (*dynamodb.AttributeValue, error)
	GenerateDataKey(ctx context.Context, encryptionContext map[string]string) ([]byte, []byte, error)
	DecryptDataKey(ctx context.Context, ciphertext []byte, encryptionContext map[string]string) ([]byte, error)
}

// CryptographicMaterialsProvider is an interface for a cryptographic materials provider
type CryptographicMaterialsProvider struct {
	cryptoProvider CryptoProvider
	description    map[string]string
}

// WrappedDataKeyAttrName is the name of the wrapped data key attribute
const WrappedDataKeyAttrName = "__wrapped_data_key"

// NewCryptographicMaterialsProvider creates a new CryptographicMaterialsProvider
func NewCryptographicMaterialsProvider(cryptoProvider CryptoProvider, description map[string]string) *CryptographicMaterialsProvider {
	return &CryptographicMaterialsProvider{
		cryptoProvider: cryptoProvider,
		description:    description,
	}
}

// EncryptionMaterials generates encryption materials
func (p *CryptographicMaterialsProvider) EncryptionMaterials(ctx context.Context, encryptionContext map[string]string) (map[string]*dynamodb.AttributeValue, error) {
	_, encryptedDataKey, err := p.cryptoProvider.GenerateDataKey(ctx, encryptionContext)
	if err != nil {
		return nil, fmt.Errorf("failed to generate data key: %v", err)
	}

	materialDescription := make(map[string]*dynamodb.AttributeValue)
	for k, v := range p.description {
		materialDescription[k] = &dynamodb.AttributeValue{S: &v}
	}
	materialDescription[WrappedDataKeyAttrName] = &dynamodb.AttributeValue{B: encryptedDataKey}

	return materialDescription, nil
}

// DecryptionMaterials generates decryption materials
func (p *CryptographicMaterialsProvider) DecryptionMaterials(ctx context.Context, encryptionContext map[string]*dynamodb.AttributeValue) (map[string]string, error) {
	encryptedDataKey := encryptionContext[WrappedDataKeyAttrName]
	ciphertext := encryptedDataKey.B

	// Remove the wrapped data key from the encryption context
	delete(encryptionContext, WrappedDataKeyAttrName)

	decryptionContext := make(map[string]string)
	for k, v := range encryptionContext {
		if v.S != nil {
			decryptionContext[k] = *v.S
		} else if v.N != nil {
			decryptionContext[k] = *v.N
		}
	}

	_, err := p.cryptoProvider.DecryptDataKey(ctx, ciphertext, decryptionContext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data key: %v", err)
	}

	return decryptionContext, nil
}
