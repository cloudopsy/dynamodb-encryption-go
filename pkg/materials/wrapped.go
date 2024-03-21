package materials

import (
	"encoding/base64"
	"fmt"

	"github.com/cloudopsy/dynamodb-encryption-go/pkg/delegatedkeys"
)

// MaterialDescription represents the material description including the algorithm and wrapped keyset.
type MaterialDescription struct {
	ContentEncryptionAlgorithm  string
	WrappedKeyset               string
	ContentKeyWrappingAlgorithm string
}

// WrappedCryptographicMaterials handles encryption keys within a material description and uses a wrapped keyset.
type WrappedCryptographicMaterials struct {
	SigningKey          delegatedkeys.DelegatedKey
	WrappingKey         delegatedkeys.DelegatedKey
	MaterialDescription MaterialDescription
}

// NewWrappedCryptographicMaterials creates a new instance of WrappedCryptographicMaterials.
func NewWrappedCryptographicMaterials(signingKey, wrappingKey delegatedkeys.DelegatedKey, materialDesc MaterialDescription) *WrappedCryptographicMaterials {
	return &WrappedCryptographicMaterials{
		SigningKey:          signingKey,
		WrappingKey:         wrappingKey,
		MaterialDescription: materialDesc,
	}
}

// WrapKeyset wraps the Tink keyset with the KEK and updates the material description.
func (wcm *WrappedCryptographicMaterials) WrapKeyset() error {
	wrappedKeyset, err := wcm.WrappingKey.WrapKeyset()
	if err != nil {
		return fmt.Errorf("failed to wrap keyset: %v", err)
	}

	// Update the material description with the wrapped keyset
	wcm.MaterialDescription = MaterialDescription{
		ContentEncryptionAlgorithm:  "Tink",
		WrappedKeyset:               base64.StdEncoding.EncodeToString(wrappedKeyset),
		ContentKeyWrappingAlgorithm: wcm.WrappingKey.Algorithm(),
	}

	return nil
}
