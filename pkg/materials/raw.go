package materials

import (
	"fmt"

	"github.com/cloudopsy/dynamodb-encryption-go/pkg/delegatedkeys"
)

// Warning: Using raw cryptographic materials can be dangerous because you are likely to be
// encrypting many items using the same encryption key material. This can have some unexpected
// and difficult to detect side effects that weaken the security of your encrypted data.
//
// Unless you have specific reasons for using raw cryptographic materials, we highly recommend
// that you use wrapped cryptographic materials instead.

// RawEncryptionMaterials defines encryption materials for use directly with delegated keys.
// Not all delegated keys allow use with raw cryptographic materials.
type RawEncryptionMaterials struct {
	SigningKey          delegatedkeys.DelegatedKey
	EncryptionKey       delegatedkeys.DelegatedKey
	MaterialDescription map[string]string
}

// NewRawEncryptionMaterials creates a new instance of RawEncryptionMaterials.
// It returns an error if the encryption key is not allowed for raw materials.
func NewRawEncryptionMaterials(signingKey, encryptionKey delegatedkeys.DelegatedKey, materialDescription map[string]string) (*RawEncryptionMaterials, error) {
	if encryptionKey != nil && !encryptionKey.AllowedForRawMaterials() {
		return nil, fmt.Errorf("encryption key type %T does not allow use with RawEncryptionMaterials", encryptionKey)
	}
	return &RawEncryptionMaterials{
		SigningKey:          signingKey,
		EncryptionKey:       encryptionKey,
		MaterialDescription: materialDescription,
	}, nil
}

// RawDecryptionMaterials defines decryption materials for use directly with delegated keys.
// Not all delegated keys allow use with raw cryptographic materials.
type RawDecryptionMaterials struct {
	VerificationKey     delegatedkeys.DelegatedKey
	DecryptionKey       delegatedkeys.DelegatedKey
	MaterialDescription map[string]string
}

// NewRawDecryptionMaterials creates a new instance of RawDecryptionMaterials.
// It returns an error if the decryption key is not allowed for raw materials.
func NewRawDecryptionMaterials(verificationKey, decryptionKey delegatedkeys.DelegatedKey, materialDescription map[string]string) (*RawDecryptionMaterials, error) {
	if decryptionKey != nil && !decryptionKey.AllowedForRawMaterials() {
		return nil, fmt.Errorf("decryption key type %T does not allow use with RawDecryptionMaterials", decryptionKey)
	}
	return &RawDecryptionMaterials{
		VerificationKey:     verificationKey,
		DecryptionKey:       decryptionKey,
		MaterialDescription: materialDescription,
	}, nil
}
