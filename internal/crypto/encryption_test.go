package crypto

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEncryptorDecryptor(t *testing.T) {
	ed, err := NewEncryptorDecryptor(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, ed.aead)
	assert.NotNil(t, ed.daead)
}

const Invalid Option = -1

func TestEncryptorDecryptor_EncryptDecryptAttribute(t *testing.T) {
	ed, err := NewEncryptorDecryptor(context.Background(), WithAttribute("test", Encrypt))
	require.NoError(t, err)

	plaintext := &dynamodb.AttributeValue{S: aws.String("hello")}
	ciphertext, err := ed.EncryptAttribute(context.Background(), "test", plaintext)
	require.NoError(t, err)
	assert.NotNil(t, ciphertext.B)

	decrypted, err := ed.DecryptAttribute(context.Background(), "test", ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptorDecryptor_EncryptDecryptAttributeDeterministically(t *testing.T) {
	ed, err := NewEncryptorDecryptor(context.Background(), WithAttribute("test", EncryptDeterministically))
	require.NoError(t, err)

	plaintext := &dynamodb.AttributeValue{S: aws.String("hello")}
	ciphertext, err := ed.EncryptAttributeDeterministically(context.Background(), "test", plaintext)
	require.NoError(t, err)
	assert.NotNil(t, ciphertext.B)

	decrypted, err := ed.DecryptAttributeDeterministically(context.Background(), "test", ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptorDecryptor_WrapUnwrapKey(t *testing.T) {
	ed, err := NewEncryptorDecryptor(context.Background())
	require.NoError(t, err)

	plaintext, ciphertext, err := ed.WrapKey()
	require.NoError(t, err)
	assert.NotEmpty(t, plaintext)
	assert.NotEmpty(t, ciphertext)

	decrypted, err := ed.UnwrapKey(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptorDecryptor_EncryptAttributeUnrecognizedAction(t *testing.T) {
	ed, err := NewEncryptorDecryptor(context.Background(), WithAttribute("test", Invalid))
	require.NoError(t, err)

	plaintext := &dynamodb.AttributeValue{S: aws.String("hello")}
	_, err = ed.EncryptAttribute(context.Background(), "test", plaintext)
	assert.Error(t, err)
}

func TestEncryptorDecryptor_DecryptAttributeUnrecognizedAction(t *testing.T) {
	ed, err := NewEncryptorDecryptor(context.Background(), WithAttribute("test", Invalid))
	require.NoError(t, err)

	ciphertext := &dynamodb.AttributeValue{B: []byte("encrypted")}
	_, err = ed.DecryptAttribute(context.Background(), "test", ciphertext)
	assert.Error(t, err)
}

func TestEncryptorDecryptor_DecryptAttributeInvalidCiphertext(t *testing.T) {
	ed, err := NewEncryptorDecryptor(context.Background(), WithAttribute("test", Encrypt))
	require.NoError(t, err)

	ciphertext := &dynamodb.AttributeValue{S: aws.String("invalid")}
	_, err = ed.DecryptAttribute(context.Background(), "test", ciphertext)
	assert.Error(t, err)
}

func TestEncryptorDecryptor_DecryptAttributeDeterministicallyInvalidCiphertext(t *testing.T) {
	ed, err := NewEncryptorDecryptor(context.Background(), WithAttribute("test", EncryptDeterministically))
	require.NoError(t, err)

	ciphertext := &dynamodb.AttributeValue{S: aws.String("invalid")}
	_, err = ed.DecryptAttributeDeterministically(context.Background(), "test", ciphertext)
	assert.Error(t, err)
}

func TestEncryptorDecryptor_UnwrapKeyEmptyCiphertext(t *testing.T) {
	ed, err := NewEncryptorDecryptor(context.Background())
	require.NoError(t, err)

	_, err = ed.UnwrapKey(nil)
	assert.Error(t, err)
}
