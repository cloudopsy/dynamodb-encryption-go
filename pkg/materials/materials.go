package materials

import (
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/delegatedkeys"
)

// CryptographicMaterials defines a common interface for cryptographic materials.
type CryptographicMaterials interface {
	MaterialDescription() map[string]string
	EncryptionKey() delegatedkeys.DelegatedKey
	DecryptionKey() delegatedkeys.DelegatedKey
	SigningKey() delegatedkeys.DelegatedKey
}

// EncryptionMaterials defines the structure for encryption materials.
type EncryptionMaterials struct {
	materialDescription map[string]string
	encryptionKey       delegatedkeys.DelegatedKey
	signingKey          delegatedkeys.DelegatedKey
}

func NewEncryptionMaterials(description map[string]string, encryptionKey, signingKey delegatedkeys.DelegatedKey) CryptographicMaterials {
	return &EncryptionMaterials{
		materialDescription: description,
		encryptionKey:       encryptionKey,
		signingKey:          signingKey,
	}
}

func (em *EncryptionMaterials) MaterialDescription() map[string]string {
	return em.materialDescription
}

func (em *EncryptionMaterials) EncryptionKey() delegatedkeys.DelegatedKey {
	return em.encryptionKey
}

// DecryptionKey panics because EncryptionMaterials does not provide a decryption key.
func (em *EncryptionMaterials) DecryptionKey() delegatedkeys.DelegatedKey {
	panic("Encryption materials do not provide decryption keys.")
}

func (em *EncryptionMaterials) SigningKey() delegatedkeys.DelegatedKey {
	return em.signingKey
}

// VerificationKey panics because EncryptionMaterials does not provide a verification key.
func (em *EncryptionMaterials) VerificationKey() delegatedkeys.DelegatedKey {
	panic("Encryption materials do not provide verification keys.")
}

// DecryptionMaterials defines the structure for decryption materials.
type DecryptionMaterials struct {
	materialDescription map[string]string
	decryptionKey       delegatedkeys.DelegatedKey
}

func NewDecryptionMaterials(description map[string]string, decryptionKey delegatedkeys.DelegatedKey) CryptographicMaterials {
	return &DecryptionMaterials{
		materialDescription: description,
		decryptionKey:       decryptionKey,
	}
}

func (dm *DecryptionMaterials) MaterialDescription() map[string]string {
	return dm.materialDescription
}

// EncryptionKey panics because DecryptionMaterials does not provide an encryption key.
func (dm *DecryptionMaterials) EncryptionKey() delegatedkeys.DelegatedKey {
	panic("Decryption materials do not provide encryption keys.")
}

func (dm *DecryptionMaterials) DecryptionKey() delegatedkeys.DelegatedKey {
	return dm.decryptionKey
}

// SigningKey panics because DecryptionMaterials does not provide a signing key.
func (dm *DecryptionMaterials) SigningKey() delegatedkeys.DelegatedKey {
	panic("Decryption materials do not provide signing keys.")
}
