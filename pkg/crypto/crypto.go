package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/tink-crypto/tink-go-awskms/integration/awskms"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/daead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// Action is an enum for encryption methods
type Action int

const (
	// Encrypt encrypts the attribute value using AEAD encryption
	Encrypt Action = iota
	// EncryptDeterministically encrypts the attribute value using Deterministic AEAD encryption
	EncryptDeterministically
	// DoNothing does not encrypt the attribute value
	DoNothing
)

type Crypto struct {
	keyURI string
	aead   tink.AEAD
	daead  tink.DeterministicAEAD
}

// New creates a new Crypto provider
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

// EncryptAttribute encrypts the attribute value using AEAD encryption
func (c *Crypto) EncryptAttribute(attributeName string, attributeValue *dynamodb.AttributeValue, method Action) (*dynamodb.AttributeValue, error) {

	var ciphertext *dynamodb.AttributeValue
	var err error
	switch method {
	case Encrypt:
		ciphertext, err = c.EncryptAttributeWithAEAD(attributeName, attributeValue)
		if err != nil {
			return nil, err
		}
	case EncryptDeterministically:
		ciphertext, err = c.EncryptAttributeWithDAEAD(attributeName, attributeValue)
		if err != nil {
			return nil, err
		}
	case DoNothing:
		return attributeValue, nil
	}

	// Extract the Base64-encoded string from the ciphertext.B field.
	encodedCiphertext := ""
	if ciphertext.B != nil {
		encodedCiphertext = base64.StdEncoding.EncodeToString(ciphertext.B)
	} else {
		return nil, fmt.Errorf("ciphertext.B is nil or ciphertext is not in expected format")
	}

	combinedMethodCiphertext := fmt.Sprintf("%d", method) + "." + encodedCiphertext

	return &dynamodb.AttributeValue{S: &combinedMethodCiphertext}, nil
}

// EncryptAttributeWithAEAD encrypts the attribute value using AEAD encryption
func (c *Crypto) EncryptAttributeWithAEAD(attributeName string, attributeValue *dynamodb.AttributeValue) (*dynamodb.AttributeValue, error) {
	var plaintext interface{}
	err := dynamodbattribute.Unmarshal(attributeValue, &plaintext)
	if err != nil {
		return nil, err
	}

	plaintextBytes, err := json.Marshal(plaintext)
	if err != nil {
		return nil, err
	}

	ciphertext, err := c.aead.Encrypt(plaintextBytes, []byte(attributeName))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt attribute: %v", err)
	}

	return &dynamodb.AttributeValue{B: []byte(ciphertext)}, nil
}

// EncryptAttributeWithDAEAD encrypts the attribute value using Deterministic AEAD encryption
func (c *Crypto) EncryptAttributeWithDAEAD(attributeName string, attributeValue *dynamodb.AttributeValue) (*dynamodb.AttributeValue, error) {
	var plaintext interface{}
	err := dynamodbattribute.Unmarshal(attributeValue, &plaintext)
	if err != nil {
		return nil, err
	}

	plaintextBytes, err := json.Marshal(plaintext)
	if err != nil {
		return nil, err
	}

	ciphertext, err := c.daead.EncryptDeterministically(plaintextBytes, []byte(attributeName))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt attribute deterministically: %v", err)
	}

	return &dynamodb.AttributeValue{B: ciphertext}, nil
}

// DecryptAttribute decrypts the attribute value using the appropriate encryption method
func (c *Crypto) DecryptAttribute(attributeName string, attributeValue *dynamodb.AttributeValue) (*dynamodb.AttributeValue, error) {
	if attributeValue.S == nil {
		return attributeValue, nil
	}

	parts := strings.SplitN(*attributeValue.S, ".", 2)
	// If the format does not match "<METHOD>.<BASE64>", return the attribute as is
	if len(parts) != 2 || !isValidMethod(parts[0]) || !isValidBase64(parts[1]) {
		return attributeValue, nil
	}

	methodInt, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse encryption method from attribute: %v", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode ciphertext: %v", err)
	}

	// Choose decryption method based on the methodInt
	var decryptedAttribute *dynamodb.AttributeValue
	switch Action(methodInt) {
	case Encrypt:
		decryptedAttribute, err = c.DecryptAttributeWithAEAD(attributeName, ciphertext)
	case EncryptDeterministically:
		decryptedAttribute, err = c.DecryptAttributeWithDAEAD(attributeName, ciphertext)
	default:
		err = fmt.Errorf("unknown encryption method: %d", methodInt)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to decrypt attribute '%s': %v", attributeName, err)
	}

	return decryptedAttribute, nil
}

// DecryptAttribute decrypts the ciphertext using AEAD encryption
func (c *Crypto) DecryptAttributeWithAEAD(attributeName string, ciphertext []byte) (*dynamodb.AttributeValue, error) {
	// Decrypt the ciphertext to plaintext
	plaintext, err := c.aead.Decrypt(ciphertext, []byte(attributeName))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt attribute '%s': %v", attributeName, err)
	}

	// Unmarshal the plaintext into an interface{}
	var attributeValue interface{}
	err = json.Unmarshal(plaintext, &attributeValue)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal plaintext into interface{}: %v", err)
	}

	// Convert the interface{} to a dynamodb.AttributeValue
	result, err := dynamodbattribute.Marshal(attributeValue)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal interface{} into dynamodb.AttributeValue: %v", err)
	}

	return result, nil
}

// DecryptAttributeDeterministically decrypts the ciphertext using Deterministic AEAD encryption
func (c *Crypto) DecryptAttributeWithDAEAD(attributeName string, ciphertext []byte) (*dynamodb.AttributeValue, error) {
	plaintext, err := c.daead.DecryptDeterministically(ciphertext, []byte(attributeName))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt attribute '%s': %v", attributeName, err)
	}

	// Unmarshal the plaintext into an interface{}
	var attributeValue interface{}
	err = json.Unmarshal(plaintext, &attributeValue)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal plaintext into interface{}: %v", err)
	}

	// Convert the interface{} to a dynamodb.AttributeValue
	result, err := dynamodbattribute.Marshal(attributeValue)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal interface{} into dynamodb.AttributeValue: %v", err)
	}

	return result, nil
}

// GenerateDataKey generates a new data key and encrypts it using the KEK
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

// DecryptDataKey decrypts the data key using the KEK
func (c *Crypto) DecryptDataKey(ciphertext []byte, encryptionContext map[string]string) ([]byte, error) {
	associatedData, err := json.Marshal(encryptionContext)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal encryption context: %v", err)
	}

	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}

	plaintext, err := c.aead.Decrypt(ciphertext, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data key: %v", err)
	}

	return plaintext, nil
}

// EncodeBase64 encodes the input data to a base64 string
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 decodes the base64 string to the original data
func DecodeBase64(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

func isValidMethod(method string) bool {
	_, err := strconv.Atoi(method)
	return err == nil // Example validation, adjust as needed
}

func isValidBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}
