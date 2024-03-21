package crypto

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/tink-crypto/tink-go-awskms/integration/awskms"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/daead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// EncryptorDecryptor encapsulates Tink's AEAD/DEAD functionality.
type EncryptorDecryptor struct {
	aead    tink.AEAD
	daead   tink.DeterministicAEAD
	options map[string]Option
}

// NewEncryptorDecryptor creates a new instance of EncryptorDecryptor with a key URI from AWS KMS.
func NewEncryptorDecryptor(ctx context.Context, options ...EncryptorOption) (*EncryptorDecryptor, error) {
	var aeadPrimitive tink.AEAD
	var err error

	aeadPrimitive, err = setupAEAD()
	if err != nil {
		return nil, err
	}

	// Setup DAEAD
	daeadPrimitive, err := setupDAEAD()
	if err != nil {
		return nil, err
	}

	ed := &EncryptorDecryptor{
		aead:    aeadPrimitive,
		daead:   daeadPrimitive,
		options: make(map[string]Option),
	}

	// Apply each option to the instance
	for _, option := range options {
		if err := option(ed); err != nil {
			return nil, err
		}
	}

	return ed, nil
}

// EncryptAttribute encrypts a DynamoDB attribute based on the specified action.
func (e *EncryptorDecryptor) EncryptAttribute(ctx context.Context, attributeName string, attributeValue types.AttributeValue) (types.AttributeValue, error) {
	action, found := e.options[attributeName]
	if !found {
		// If no specific action is found, use the default action.
		action = e.options["__default__"]
	}

	switch action {
	case DoNothing:
		return attributeValue, nil
	case EncryptDeterministically:
		plaintext, err := marshalAttributeValue(attributeValue)
		if err != nil {
			return &types.AttributeValueMemberNULL{Value: true}, err
		}
		ciphertext, err := e.daead.EncryptDeterministically(plaintext, []byte(attributeName))
		if err != nil {
			return &types.AttributeValueMemberNULL{Value: true}, fmt.Errorf("failed to deterministically encrypt attribute: %v", err)
		}
		return &types.AttributeValueMemberB{Value: ciphertext}, nil
	case Encrypt:
		plaintext, err := marshalAttributeValue(attributeValue)
		if err != nil {
			return &types.AttributeValueMemberNULL{Value: true}, err
		}
		ciphertext, err := e.aead.Encrypt(plaintext, []byte(attributeName))
		if err != nil {
			return &types.AttributeValueMemberNULL{Value: true}, fmt.Errorf("failed to encrypt attribute: %v", err)
		}
		return &types.AttributeValueMemberB{Value: ciphertext}, nil
	default:
		return &types.AttributeValueMemberNULL{Value: true}, fmt.Errorf("unrecognized action %v for attribute '%s'", action, attributeName)
	}
}

// DecryptAttribute decrypts a DynamoDB attribute based on the specified action.
func (e *EncryptorDecryptor) DecryptAttribute(ctx context.Context, attributeName string, attributeValue types.AttributeValue) (types.AttributeValue, error) {
	option, found := e.options[attributeName]
	if !found {
		// If no specific action is found, use the default action.
		option = e.options["__default__"]
	}

	switch option {
	case DoNothing:
		return attributeValue, nil
	case EncryptDeterministically:
		ciphertext, ok := attributeValue.(*types.AttributeValueMemberB)
		if !ok {
			return &types.AttributeValueMemberNULL{Value: true}, fmt.Errorf("attribute value is not a binary(B)")
		}
		plaintext, err := e.daead.DecryptDeterministically(ciphertext.Value, []byte(attributeName))
		if err != nil {
			return &types.AttributeValueMemberNULL{Value: true}, fmt.Errorf("failed to deterministically decrypt attribute: %v", err)
		}
		return unmarshalAttributeValue(plaintext)
	case Encrypt:
		ciphertext, ok := attributeValue.(*types.AttributeValueMemberB)
		if !ok {
			return &types.AttributeValueMemberNULL{Value: true}, fmt.Errorf("attribute value is not a binary(B)")
		}
		plaintext, err := e.aead.Decrypt(ciphertext.Value, []byte(attributeName))
		if err != nil {
			return &types.AttributeValueMemberNULL{Value: true}, fmt.Errorf("failed to decrypt attribute: %v", err)
		}
		return unmarshalAttributeValue(plaintext)
	default:
		return &types.AttributeValueMemberNULL{Value: true}, fmt.Errorf("unrecognized option %v for attribute '%s'", option, attributeName)
	}
}

// EncryptAttributeDeterministically encrypts a DynamoDB attribute deterministically.
func (e *EncryptorDecryptor) EncryptAttributeDeterministically(ctx context.Context, attributeName string, attributeValue types.AttributeValue) (types.AttributeValue, error) {
	plaintext, err := marshalAttributeValue(attributeValue)
	if err != nil {
		return &types.AttributeValueMemberNULL{Value: true}, err
	}

	ciphertext, err := e.daead.EncryptDeterministically(plaintext, []byte(attributeName))
	if err != nil {
		return &types.AttributeValueMemberNULL{Value: true}, fmt.Errorf("failed to deterministically encrypt attribute: %v", err)
	}

	return &types.AttributeValueMemberB{Value: ciphertext}, nil
}

// DecryptAttributeDeterministically decrypts a DynamoDB attribute deterministically.
func (e *EncryptorDecryptor) DecryptAttributeDeterministically(ctx context.Context, attributeName string, attributeValue types.AttributeValue) (types.AttributeValue, error) {
	ciphertext, ok := attributeValue.(*types.AttributeValueMemberB)
	if !ok {
		return &types.AttributeValueMemberNULL{Value: true}, fmt.Errorf("attribute value is not a binary(B)")
	}

	plaintext, err := e.daead.DecryptDeterministically(ciphertext.Value, []byte(attributeName))
	if err != nil {
		return &types.AttributeValueMemberNULL{Value: true}, fmt.Errorf("failed to deterministically decrypt attribute: %v", err)
	}

	return unmarshalAttributeValue(plaintext)
}

// WrapKey generates a new data key and encrypts it
func (e *EncryptorDecryptor) WrapKey() ([]byte, []byte, error) {
	plaintext, err := e.generateRandomKey(32)
	if err != nil {
		return nil, nil, err
	}

	ciphertext, err := e.aead.Encrypt(plaintext, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt data key: %v", err)
	}

	return plaintext, ciphertext, nil
}

// UnwrapKey decrypts the data key using the KEK
func (e *EncryptorDecryptor) UnwrapKey(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}

	plaintext, err := e.aead.Decrypt(ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data key: %v", err)
	}

	return plaintext, nil
}

func setupKmsEnvelopeAEAD(keyURI string) (tink.AEAD, error) {
	client, err := awskms.NewClientWithOptions(keyURI)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS KMS client: %v", err)
	}
	kek, err := client.GetAEAD(keyURI)
	if err != nil {
		return nil, fmt.Errorf("failed to get AEAD primitive from KMS: %v", err)
	}
	return aead.NewKMSEnvelopeAEAD2(aead.AES256GCMKeyTemplate(), kek), nil
}

func setupAEAD() (tink.AEAD, error) {
	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		return nil, fmt.Errorf("failed to create local key handle: %v", err)
	}
	return aead.New(kh)
}

func setupDAEAD() (tink.DeterministicAEAD, error) {
	kh, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
	if err != nil {
		return nil, fmt.Errorf("failed to create DAEAD key handle: %v", err)
	}
	return daead.New(kh)
}

func (e *EncryptorDecryptor) generateRandomKey(bytes int) ([]byte, error) {
	plaintext := make([]byte, bytes)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, fmt.Errorf("failed to generate data key: %v", err)
	}

	return plaintext, nil
}
