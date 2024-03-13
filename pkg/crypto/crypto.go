// crypto.go
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
	aead  tink.AEAD
	daead tink.DeterministicAEAD
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
		aead:  envelopeAEAD,
		daead: deterministicAEAD,
	}, nil
}

func (c *Crypto) EncryptAttribute(attributeName string, attribute interface{}) ([]byte, error) {
	serializedAttribute, err := SerializeAttribute(attribute)
	if err != nil {
		return nil, err
	}

	associatedData := []byte(attributeName)
	ciphertext, err := c.aead.Encrypt(serializedAttribute, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt attribute: %v", err)
	}

	return ciphertext, nil
}

func (c *Crypto) DecryptAttribute(attributeName string, ciphertext []byte) (interface{}, error) {
	associatedData := []byte(attributeName)
	plaintext, err := c.aead.Decrypt(ciphertext, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt attribute: %v", err)
	}

	attribute, err := DeserializeAttribute(plaintext)
	if err != nil {
		return nil, err
	}

	return attribute, nil
}

func (c *Crypto) EncryptAttributeDeterministically(attributeName string, attribute interface{}) ([]byte, error) {
	serializedAttribute, err := SerializeAttribute(attribute)
	if err != nil {
		return nil, err
	}

	associatedData := []byte(attributeName)
	ciphertext, err := c.daead.EncryptDeterministically(serializedAttribute, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt attribute deterministically: %v", err)
	}

	return ciphertext, nil
}

func (c *Crypto) DecryptAttributeDeterministically(attributeName string, ciphertext []byte) (interface{}, error) {
	associatedData := []byte(attributeName)
	plaintext, err := c.daead.DecryptDeterministically(ciphertext, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt attribute deterministically: %v", err)
	}

	attribute, err := DeserializeAttribute(plaintext)
	if err != nil {
		return nil, err
	}

	return attribute, nil
}

func SerializeAttribute(attribute interface{}) ([]byte, error) {
	return json.Marshal(attribute)
}

func DeserializeAttribute(data []byte) (interface{}, error) {
	var attribute interface{}
	err := json.Unmarshal(data, &attribute)
	return attribute, err
}

func SerializeItem(item map[string]interface{}) ([]byte, error) {
	return json.Marshal(item)
}

func DeserializeItem(data []byte) (map[string]interface{}, error) {
	var item map[string]interface{}
	err := json.Unmarshal(data, &item)
	return item, err
}

func GenerateDataKey(keyURI string, encryptionContext map[string]string) ([]byte, []byte, error) {
	client, err := awskms.NewClientWithOptions(keyURI)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AWS KMS client: %v", err)
	}

	aead, err := client.GetAEAD(keyURI)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get AEAD primitive: %v", err)
	}

	plaintext := make([]byte, 32)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, nil, fmt.Errorf("failed to generate data key: %v", err)
	}

	associatedData, err := json.Marshal(encryptionContext)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal encryption context: %v", err)
	}

	ciphertext, err := aead.Encrypt(plaintext, associatedData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt data key: %v", err)
	}

	return plaintext, ciphertext, nil
}

func DecryptDataKey(keyURI string, ciphertext []byte, encryptionContext map[string]string) ([]byte, error) {
	client, err := awskms.NewClientWithOptions(keyURI)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS KMS client: %v", err)
	}

	aead, err := client.GetAEAD(keyURI)
	if err != nil {
		return nil, fmt.Errorf("failed to get AEAD primitive: %v", err)
	}

	associatedData, err := json.Marshal(encryptionContext)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal encryption context: %v", err)
	}

	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}

	plaintext, err := aead.Decrypt(ciphertext, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data key: %v", err)
	}

	return plaintext, nil
}

func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func DecodeBase64(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}
