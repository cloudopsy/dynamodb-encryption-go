package delegatedkeys

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/tink-crypto/tink-go-awskms/integration/awskms"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/daead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature"
)

// DelegatedKey is an interface for keys that support encryption, decryption, signing,
// and unwrapping.
type DelegatedKey interface {
	// Algorithm returns the name of the algorithm used by the delegated key.
	Algorithm() string

	// AllowedForRawMaterials indicates if the key can be used with raw cryptographic materials.
	AllowedForRawMaterials() bool

	// Encrypt encrypts the given plaintext using the algorithm specified by the key.
	Encrypt(plaintext []byte, associatedData []byte) (ciphertext []byte, err error)

	// Decrypt decrypts the given ciphertext using the algorithm specified by the key.
	Decrypt(ciphertext []byte, associatedData []byte) (plaintext []byte, err error)

	// Sign signs the given data using the algorithm specified by the key.
	Sign(data []byte) (signature []byte, err error)

	// Verify verifies the given signature for the data using the algorithm specified by the key.
	Verify(signature []byte, data []byte) (valid bool, err error)

	// WrapKeyset wraps the keyset using the algorithm specified by the key.
	WrapKeyset() (wrappedKeyset []byte, err error)
}

type TinkDelegatedKey struct {
	keysetHandle *keyset.Handle
	kekUri       string
}

func NewTinkDelegatedKey(kh *keyset.Handle, kekUri string) *TinkDelegatedKey {
	return &TinkDelegatedKey{keysetHandle: kh, kekUri: kekUri}
}

func (dk *TinkDelegatedKey) Algorithm() string {
	typeUrl := dk.keysetHandle.KeysetInfo().KeyInfo[0].TypeUrl

	parts := strings.Split(typeUrl, ".")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return "Unknown"
}

func (dk *TinkDelegatedKey) AllowedForRawMaterials() bool {
	// Implement logic based on your application's requirements.
	return true
}

func (dk *TinkDelegatedKey) Encrypt(plaintext []byte, associatedData []byte) ([]byte, error) {
	a, err := aead.New(dk.keysetHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to get AEAD primitive: %v", err)
	}
	return a.Encrypt(plaintext, associatedData)
}

func (dk *TinkDelegatedKey) Decrypt(ciphertext []byte, associatedData []byte) ([]byte, error) {
	a, err := aead.New(dk.keysetHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to get AEAD primitive: %v", err)
	}
	return a.Decrypt(ciphertext, associatedData)
}

// Sign signs the given data using the keyset's primary key.
func (dk *TinkDelegatedKey) Sign(data []byte) ([]byte, error) {
	signer, err := signature.NewSigner(dk.keysetHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %v", err)
	}
	signature, err := signer.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %v", err)
	}
	return signature, nil
}

// Verify verifies the given signature for the data using the keyset's primary key.
func (dk *TinkDelegatedKey) Verify(sign []byte, data []byte) (bool, error) {
	verifier, err := signature.NewVerifier(dk.keysetHandle)
	if err != nil {
		return false, fmt.Errorf("failed to create verifier: %v", err)
	}
	err = verifier.Verify(sign, data)
	if err != nil {
		return false, fmt.Errorf("failed to verify signature: %v", err)
	}
	return true, nil
}

// WrapKeyset wraps the Tink keyset with the KEK.
func (dk *TinkDelegatedKey) WrapKeyset() ([]byte, error) {
	client, err := awskms.NewClientWithOptions(dk.kekUri)
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS client: %v", err)
	}
	kekAEAD, err := client.GetAEAD(dk.kekUri)
	if err != nil {
		return nil, fmt.Errorf("failed to get KEK AEAD: %v", err)
	}

	buf := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(buf)
	if err := dk.keysetHandle.Write(writer, kekAEAD); err != nil {
		return nil, fmt.Errorf("failed to wrap keyset: %v", err)
	}

	return buf.Bytes(), nil
}

// UnwrapKeyset unwraps the Tink keyset using the KEK.
func UnwrapKeyset(encryptedKeyset []byte, kekUri string) (*TinkDelegatedKey, error) {
	client, err := awskms.NewClientWithOptions(kekUri)
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS client: %v", err)
	}
	kekAEAD, err := client.GetAEAD(kekUri)
	if err != nil {
		return nil, fmt.Errorf("failed to get KEK AEAD: %v", err)
	}

	reader := keyset.NewBinaryReader(bytes.NewReader(encryptedKeyset))
	handle, err := keyset.Read(reader, kekAEAD)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap keyset: %v", err)
	}

	return NewTinkDelegatedKey(handle, kekUri), nil
}

func GenerateDataKey(keyURI, keyType string) (*TinkDelegatedKey, []byte, error) {
	var kh *keyset.Handle
	var err error

	switch strings.ToLower(keyType) {
	case "aead":
		kh, err = keyset.NewHandle(aead.AES256GCMKeyTemplate())
	case "daead":
		kh, err = keyset.NewHandle(daead.AESSIVKeyTemplate())
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %v", keyType)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate new keyset handle for %v: %v", keyType, err)
	}

	delegatedKey := NewTinkDelegatedKey(kh, keyURI)
	wrappedKeyset, err := delegatedKey.WrapKeyset()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to wrap keyset: %v", err)
	}

	return delegatedKey, wrappedKeyset, nil
}
