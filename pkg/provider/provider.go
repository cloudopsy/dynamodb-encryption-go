package provider

import (
	"context"

	"github.com/aws/aws-sdk-go/service/dynamodb"
)

// CryptographicMaterialsProvider is an interface for handling cryptographic materials.
type CryptographicMaterialsProvider interface {
	EncryptionMaterials(ctx context.Context, encryptionContext map[string]*dynamodb.AttributeValue) (map[string]*dynamodb.AttributeValue, error)
	DecryptionMaterials(ctx context.Context, encryptionContext map[string]*dynamodb.AttributeValue) (map[string]*dynamodb.AttributeValue, error)
	EncryptAttribute(ctx context.Context, attributeName string, attributeValue *dynamodb.AttributeValue) (*dynamodb.AttributeValue, error)
	DecryptAttribute(ctx context.Context, attributeName string, encryptedValue *dynamodb.AttributeValue) (*dynamodb.AttributeValue, error)
}
