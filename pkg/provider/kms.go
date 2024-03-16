package provider

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/cloudopsy/dynamodb-encryption-go/internal/crypto"
)

type AwsKmsCryptographicMaterialsProvider struct {
	encryptorDecryptor *crypto.EncryptorDecryptor
}

// NewsCryptographicMaterialsProvider initializes a new AWS KMS Cryptographic Materials Provider.
func NewsCryptographicMaterialsProvider(opts ...crypto.EncryptorOption) *AwsKmsCryptographicMaterialsProvider {
	ed, err := crypto.NewEncryptorDecryptor(context.Background(), opts...)
	if err != nil {
		panic(fmt.Errorf("failed to create EncryptorDecryptor: %w", err))
	}
	return &AwsKmsCryptographicMaterialsProvider{
		encryptorDecryptor: ed,
	}
}

// EncryptionMaterials generates encryption materials using AWS KMS and your EncryptorDecryptor.
func (p *AwsKmsCryptographicMaterialsProvider) EncryptionMaterials(ctx context.Context, encryptionContext map[string]types.AttributeValue) (map[string]types.AttributeValue, error) {
	return nil, nil
}

// DecryptionMaterials generates decryption materials using AWS KMS and your EncryptorDecryptor.
func (p *AwsKmsCryptographicMaterialsProvider) DecryptionMaterials(ctx context.Context, encryptionContext map[string]types.AttributeValue) (map[string]types.AttributeValue, error) {
	return nil, nil
}

// EncryptAttribute leverages the EncryptorDecryptor to encrypt DynamoDB attributes.
func (p *AwsKmsCryptographicMaterialsProvider) EncryptAttribute(ctx context.Context, attributeName string, attributeValue types.AttributeValue) (types.AttributeValue, error) {
	return p.encryptorDecryptor.EncryptAttribute(ctx, attributeName, attributeValue)
}

// DecryptAttribute leverages the EncryptorDecryptor to decrypt DynamoDB attributes.
func (p *AwsKmsCryptographicMaterialsProvider) DecryptAttribute(ctx context.Context, attributeName string, encryptedValue types.AttributeValue) (types.AttributeValue, error) {
	return p.encryptorDecryptor.DecryptAttribute(ctx, attributeName, encryptedValue)
}
