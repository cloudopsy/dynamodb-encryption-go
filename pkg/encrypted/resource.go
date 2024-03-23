package encrypted

import (
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/provider"
)

// EncryptedResource provides a high-level interface to work with encrypted DynamoDB resources.
type EncryptedResource struct {
	Client            *EncryptedClient
	MaterialsProvider provider.CryptographicMaterialsProvider
	ClientConfig      *ClientConfig
}

// NewEncryptedResource creates a new instance of EncryptedResource.
func NewEncryptedResource(client *EncryptedClient, materialsProvider provider.CryptographicMaterialsProvider, clientConfig *ClientConfig) *EncryptedResource {
	return &EncryptedResource{
		Client:            client,
		MaterialsProvider: materialsProvider,
		ClientConfig:      clientConfig,
	}
}

// Table returns an EncryptedTable instance for the specified table name.
func (r *EncryptedResource) Table(name string) *EncryptedTable {
	return NewEncryptedTable(r.Client)
}
