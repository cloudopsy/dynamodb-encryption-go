package provider

import (
	"context"

	"github.com/cloudopsy/dynamodb-encryption-go/pkg/materials"
)

type CryptographicMaterialsProvider interface {
	EncryptionMaterials(ctx context.Context, materialName string) (materials.CryptographicMaterials, error)
	DecryptionMaterials(ctx context.Context, materialName string, version int64) (materials.CryptographicMaterials, error)
	TableName() string
}
