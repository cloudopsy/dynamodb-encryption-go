package encrypted

import (
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/provider"
)

// EncryptedResource provides a high-level interface to work with encrypted DynamoDB resources.
type EncryptedResource struct {
	Client            *EncryptedClient
	MaterialsProvider provider.CryptographicMaterialsProvider
	AttributeActions  *AttributeActions
}

// NewEncryptedResource creates a new instance of EncryptedResource.
func NewEncryptedResource(client *EncryptedClient, materialsProvider provider.CryptographicMaterialsProvider, attributeActions *AttributeActions) *EncryptedResource {
	return &EncryptedResource{
		Client:            client,
		MaterialsProvider: materialsProvider,
		AttributeActions:  attributeActions,
	}
}

// Table returns an EncryptedTable instance for the specified table name.
func (r *EncryptedResource) Table(name string) *EncryptedTable {
	return NewEncryptedTable(r.Client)
}
