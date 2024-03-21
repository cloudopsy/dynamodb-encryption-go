package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/tink-crypto/tink-go-awskms/integration/awskms"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/daead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

type Crypto struct {
	keyURI string
	aead   tink.AEAD
	daead  tink.DeterministicAEAD
}

func New(keyURI string) (*Crypto, error) {
	client, err := awskms.NewClientWithOptions(keyURI)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS KMS client: %v", err)
	}

	kekAEAD, err := client.GetAEAD(keyURI)
	if err != nil {
		return nil, fmt.Errorf("failed to get AEAD primitive: %v", err)
	}

	envelopeAEAD := aead.NewKMSEnvelopeAEAD2(aead.AES256GCMKeyTemplate(), kekAEAD)

	deterministicAEADKeyHandle, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
	if err != nil {
		return nil, fmt.Errorf("failed to create deterministic AEAD key handle: %v", err)
	}
	deterministicAEAD, err := daead.New(deterministicAEADKeyHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to create deterministic AEAD primitive: %v", err)
	}

	return &Crypto{
		keyURI: keyURI,
		aead:   envelopeAEAD,
		daead:  deterministicAEAD,
	}, nil
}

func (c *Crypto) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	return c.aead.Encrypt(plaintext, associatedData)
}

func (c *Crypto) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	return c.aead.Decrypt(ciphertext, associatedData)
}

func (c *Crypto) EncryptDeterministically(plaintext, associatedData []byte) ([]byte, error) {
	return c.daead.EncryptDeterministically(plaintext, associatedData)
}

func (c *Crypto) DecryptDeterministically(ciphertext, associatedData []byte) ([]byte, error) {
	return c.daead.DecryptDeterministically(ciphertext, associatedData)
}

func (c *Crypto) GenerateDataKey(encryptionContext map[string]string) ([]byte, []byte, error) {
	plaintext := make([]byte, 32)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, nil, fmt.Errorf("failed to generate data key: %v", err)
	}

	associatedData, err := json.Marshal(encryptionContext)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal encryption context: %v", err)
	}

	ciphertext, err := c.aead.Encrypt(plaintext, associatedData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt data key: %v", err)
	}

	return plaintext, ciphertext, nil
}

func (c *Crypto) DecryptDataKey(ciphertext []byte, encryptionContext map[string]string) ([]byte, error) {
	associatedData, err := json.Marshal(encryptionContext)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal encryption context: %v", err)
	}

	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}

	return c.aead.Decrypt(ciphertext, associatedData)
}

func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func DecodeBase64(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}
