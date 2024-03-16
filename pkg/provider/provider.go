package provider

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// CryptographicMaterialsProvider is an interface for handling cryptographic materials.
type CryptographicMaterialsProvider interface {
	EncryptionMaterials(ctx context.Context, encryptionContext map[string]types.AttributeValue) (map[string]types.AttributeValue, error)
	DecryptionMaterials(ctx context.Context, encryptionContext map[string]types.AttributeValue) (map[string]types.AttributeValue, error)
	EncryptAttribute(ctx context.Context, attributeName string, attributeValue types.AttributeValue) (types.AttributeValue, error)
	DecryptAttribute(ctx context.Context, attributeName string, encryptedValue types.AttributeValue) (types.AttributeValue, error)
}
