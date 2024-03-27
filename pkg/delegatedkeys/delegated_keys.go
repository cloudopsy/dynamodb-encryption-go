package delegatedkeys

import (
	"bytes"
	"fmt"
	"strings"
	"sync"

	fakeawskms "github.com/cloudopsy/dynamodb-encryption-go/internal/fakekms"
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
	kek             tink.AEAD
	aeadPrimitive   tink.AEAD
	signerPrimitive tink.Signer
	aeadOnce        sync.Once
	signerOnce      sync.Once
}

func NewTinkDelegatedKey(kh *keyset.Handle, kek tink.AEAD) *TinkDelegatedKey {
	return &TinkDelegatedKey{
		keysetHandle: kh,
		kek:          kek,
	}
}

func (dk *TinkDelegatedKey) Algorithm() string {
	typeURL := dk.keysetHandle.KeysetInfo().KeyInfo[0].TypeUrl
	parts := strings.Split(typeURL, ".")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return "Unknown"
}

func (dk *TinkDelegatedKey) AllowedForRawMaterials() bool {
	return true
}

func (dk *TinkDelegatedKey) Encrypt(plaintext []byte, associatedData []byte) ([]byte, error) {
	aead, err := dk.getAEADPrimitive()
	if err != nil {
		return nil, fmt.Errorf("failed to get AEAD primitive: %v", err)
	}
	return aead.Encrypt(plaintext, associatedData)
}

func (dk *TinkDelegatedKey) Decrypt(ciphertext []byte, associatedData []byte) ([]byte, error) {
	aead, err := dk.getAEADPrimitive()
	if err != nil {
		return nil, fmt.Errorf("failed to get AEAD primitive: %v", err)
	}
	return aead.Decrypt(ciphertext, associatedData)
}

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

func (dk *TinkDelegatedKey) WrapKeyset() ([]byte, error) {
	buf := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(buf)
	if err := dk.keysetHandle.Write(writer, dk.kek); err != nil {
		return nil, fmt.Errorf("failed to wrap keyset: %v", err)
	}
	return buf.Bytes(), nil
}

func UnwrapKeyset(encryptedKeyset []byte, kek tink.AEAD) (*TinkDelegatedKey, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(encryptedKeyset))
	handle, err := keyset.Read(reader, kek)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap keyset: %v", err)
	}
	return NewTinkDelegatedKey(handle, kek), nil
}

func GenerateDataKey(kek tink.AEAD) (*TinkDelegatedKey, []byte, error) {
	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate new keyset handle: %v", err)
	}
	delegatedKey := NewTinkDelegatedKey(kh, kek)
	wrappedKeyset, err := delegatedKey.WrapKeyset()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to wrap keyset: %v", err)
	}
	return delegatedKey, wrappedKeyset, nil
}

func GenerateSigningKey(kek tink.AEAD) (*TinkDelegatedKey, []byte, []byte, error) {
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate new keyset handle: %v", err)
	}
	publicKeysetHandle, err := kh.Public()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to extract public key: %v", err)
	}
	var publicKeyBytes bytes.Buffer
	publicKeyWriter := keyset.NewBinaryWriter(&publicKeyBytes)
	if err := publicKeysetHandle.WriteWithNoSecrets(publicKeyWriter); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to serialize public key: %v", err)
	}
	delegatedKey := NewTinkDelegatedKey(kh, kek)
	wrappedKeyset, err := delegatedKey.WrapKeyset()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to wrap keyset: %v", err)
	}
	return delegatedKey, wrappedKeyset, publicKeyBytes.Bytes(), nil
}

func VerifySignature(publicKeyBytes, sig, data []byte) (bool, error) {
	publicKeyReader := keyset.NewBinaryReader(bytes.NewReader(publicKeyBytes))
	publicKeyHandle, err := keyset.ReadWithNoSecrets(publicKeyReader)
	if err != nil {
		return false, fmt.Errorf("failed to load public key: %v", err)
	}
	verifier, err := signature.NewVerifier(publicKeyHandle)
	if err != nil {
		return false, fmt.Errorf("failed to get verifier: %v", err)
	}
	err = verifier.Verify(sig, data)
	if err != nil {
		return false, nil
	}
	return true, nil
}

func GetKEK(kmsKeyARN string, isTesting bool) (tink.AEAD, error) {
	if isTesting {
		// Use fake-kms for testing
		fakekms, err := fakeawskms.New([]string{kmsKeyARN})
		if err != nil {
			return nil, err
		}
		client, err := awskms.NewClientWithOptions("aws-kms://", awskms.WithKMS(fakekms))
		if err != nil {
			return nil, err
		}
		return client.GetAEAD("aws-kms://" + kmsKeyARN)
	} else {
		// Use real AWS KMS for non-testing
		client, err := awskms.NewClientWithOptions("aws-kms://" + kmsKeyARN)
		if err != nil {
			return nil, err
		}
		return client.GetAEAD("aws-kms://" + kmsKeyARN)
	}
}

func (dk *TinkDelegatedKey) getAEADPrimitive() (tink.AEAD, error) {
	var err error
	dk.aeadOnce.Do(func() {
		dk.aeadPrimitive, err = aead.New(dk.keysetHandle)
	})
	return dk.aeadPrimitive, err
}

func (dk *TinkDelegatedKey) getSignerPrimitive() (tink.Signer, error) {
	var err error
	dk.signerOnce.Do(func() {
		dk.signerPrimitive, err = signature.NewSigner(dk.keysetHandle)
	})
	return dk.signerPrimitive, err
}
