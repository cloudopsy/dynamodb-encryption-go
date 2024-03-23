package delegatedkeys

import (
	"bytes"
	"fmt"
	"strings"
	"sync"

	"github.com/tink-crypto/tink-go-awskms/integration/awskms"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/tink"
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

	// WrapKeyset wraps the keyset using the algorithm specified by the key.
	WrapKeyset() (wrappedKeyset []byte, err error)
}

type TinkDelegatedKey struct {
	keysetHandle    *keyset.Handle
	kekUri          string
	aeadPrimitive   tink.AEAD
	signerPrimitive tink.Signer
	aeadOnce        sync.Once
	signerOnce      sync.Once
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

// getAEADPrimitive lazily initializes the AEAD primitive.
func (dk *TinkDelegatedKey) getAEADPrimitive() (tink.AEAD, error) {
	var err error
	dk.aeadOnce.Do(func() {
		dk.aeadPrimitive, err = aead.New(dk.keysetHandle)
	})
	return dk.aeadPrimitive, err
}

// getSignerPrimitive lazily initializes the Signer primitive.
func (dk *TinkDelegatedKey) getSignerPrimitive() (tink.Signer, error) {
	var err error
	dk.signerOnce.Do(func() {
		dk.signerPrimitive, err = signature.NewSigner(dk.keysetHandle)
	})
	return dk.signerPrimitive, err
}

func (dk *TinkDelegatedKey) AllowedForRawMaterials() bool {
	return true
}

func (dk *TinkDelegatedKey) Encrypt(plaintext []byte, associatedData []byte) ([]byte, error) {
	a, err := dk.getAEADPrimitive()
	if err != nil {
		return nil, fmt.Errorf("failed to get AEAD primitive: %v", err)
	}
	return a.Encrypt(plaintext, associatedData)
}

func (dk *TinkDelegatedKey) Decrypt(ciphertext []byte, associatedData []byte) ([]byte, error) {
	a, err := dk.getAEADPrimitive()
	if err != nil {
		return nil, fmt.Errorf("failed to get AEAD primitive: %v", err)
	}
	return a.Decrypt(ciphertext, associatedData)
}

// Sign signs the given data using the keyset's primary key.
func (dk *TinkDelegatedKey) Sign(data []byte) ([]byte, error) {
	signer, err := dk.getSignerPrimitive()
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %v", err)
	}
	signature, err := signer.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %v", err)
	}
	return signature, nil
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

func GenerateDataKey(keyURI string) (*TinkDelegatedKey, []byte, error) {
	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())

	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate new keyset handle: %v", err)
	}

	delegatedKey := NewTinkDelegatedKey(kh, keyURI)
	wrappedKeyset, err := delegatedKey.WrapKeyset()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to wrap keyset: %v", err)
	}

	return delegatedKey, wrappedKeyset, nil
}

func GenerateSigningKey(keyURI string) (*TinkDelegatedKey, []byte, []byte, error) {
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate new keyset handle: %v", err)
	}

	// Extract the public key
	publicKeysetHandle, err := kh.Public()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to extract public key: %v", err)
	}

	var publicKeyBytes bytes.Buffer
	publicKeyWriter := keyset.NewBinaryWriter(&publicKeyBytes)
	if err := publicKeysetHandle.WriteWithNoSecrets(publicKeyWriter); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to serialize public key: %v", err)
	}

	delegatedKey := NewTinkDelegatedKey(kh, keyURI)
	wrappedKeyset, err := delegatedKey.WrapKeyset()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to wrap keyset: %v", err)
	}

	return delegatedKey, wrappedKeyset, publicKeyBytes.Bytes(), nil
}

func VerifySignature(publicKeyBytes, sig, data []byte) (bool, error) {
	// Load the public key into a keyset.Handle
	publicKeyReader := keyset.NewBinaryReader(bytes.NewReader(publicKeyBytes))
	publicKeyHandle, err := keyset.ReadWithNoSecrets(publicKeyReader)
	if err != nil {
		return false, fmt.Errorf("failed to load public key: %v", err)
	}

	// Get a Verifier instance from the public key handle
	verifier, err := signature.NewVerifier(publicKeyHandle)
	if err != nil {
		return false, fmt.Errorf("failed to get verifier: %v", err)
	}

	// Verify the signature
	err = verifier.Verify(sig, data)
	if err != nil {
		return false, nil
	}

	return true, nil
}
