package materials

import (
	"github.com/tink-crypto/tink-go/v2/tink"
)

type EncryptionMaterials struct {
	EncryptionKey        tink.AEAD
	DeterministicAEADKey tink.DeterministicAEAD
	SigningKey           tink.MAC
	Description          map[string]string
}

type DecryptionMaterials struct {
	DecryptionKey        tink.AEAD
	DeterministicAEADKey tink.DeterministicAEAD
	VerificationKey      tink.MAC
	Description          map[string]string
}
