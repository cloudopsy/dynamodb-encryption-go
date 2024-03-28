package delegatedkeys

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature"
)

const (
	keyURI = "arn:aws:kms:eu-west-2:123456789123:key/02813db0-b23a-420c-94b0-bdceb08e121b"
)

func TestTinkDelegatedKey_Encrypt_Decrypt(t *testing.T) {
	kek, err := GetKEK(keyURI, true)
	if err != nil {
		t.Fatalf("failed to get KEK: %v", err)
	}

	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatalf("failed to create keyset handle: %v", err)
	}

	dk := NewTinkDelegatedKey(kh, kek)

	plaintext := []byte("hello, world!")
	associatedData := []byte("some associated data")

	ciphertext, err := dk.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	decrypted, err := dk.Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if !cmp.Equal(plaintext, decrypted) {
		t.Errorf("decrypted data doesn't match the original plaintext")
	}
}

func TestTinkDelegatedKey_Sign_Verify(t *testing.T) {
	kek, err := GetKEK(keyURI, true)
	if err != nil {
		t.Fatalf("failed to get KEK: %v", err)
	}

	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("failed to create keyset handle: %v", err)
	}

	dk := NewTinkDelegatedKey(kh, kek)

	data := []byte("data to be signed")

	sig, err := dk.Sign(data)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	publicKeysetHandle, err := kh.Public()
	if err != nil {
		t.Fatalf("failed to get public keyset handle: %v", err)
	}

	verifier, err := signature.NewVerifier(publicKeysetHandle)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	if err := verifier.Verify(sig, data); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

func TestGenerateDataKey(t *testing.T) {
	kek, err := GetKEK(keyURI, true)
	if err != nil {
		t.Fatalf("failed to get KEK: %v", err)
	}

	dk, wrappedKeyset, err := GenerateDataKey(kek)
	if err != nil {
		t.Fatalf("failed to generate data key: %v", err)
	}

	if dk == nil {
		t.Error("generated data key is nil")
	}

	if len(wrappedKeyset) == 0 {
		t.Error("wrapped keyset is empty")
	}
}

func TestGenerateSigningKey(t *testing.T) {
	kek, err := GetKEK(keyURI, true)
	if err != nil {
		t.Fatalf("failed to get KEK: %v", err)
	}

	dk, wrappedKeyset, publicKeyBytes, err := GenerateSigningKey(kek)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}

	if dk == nil {
		t.Error("generated signing key is nil")
	}

	if len(wrappedKeyset) == 0 {
		t.Error("wrapped keyset is empty")
	}

	if len(publicKeyBytes) == 0 {
		t.Error("public key bytes are empty")
	}
}

func TestVerifySignature(t *testing.T) {
	kek, err := GetKEK(keyURI, true)
	if err != nil {
		t.Fatalf("failed to get KEK: %v", err)
	}

	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("failed to create keyset handle: %v", err)
	}

	dk := NewTinkDelegatedKey(kh, kek)

	data := []byte("data to be signed")
	sig, err := dk.Sign(data)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	publicKeysetHandle, err := kh.Public()
	if err != nil {
		t.Fatalf("failed to get public keyset handle: %v", err)
	}

	var publicKeyBuf bytes.Buffer
	publicKeyWriter := keyset.NewBinaryWriter(&publicKeyBuf)
	if err := publicKeysetHandle.WriteWithNoSecrets(publicKeyWriter); err != nil {
		t.Fatalf("failed to serialize public key: %v", err)
	}
	publicKeyBytes := publicKeyBuf.Bytes()

	valid, err := VerifySignature(publicKeyBytes, sig, data)
	if err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}

	if !valid {
		t.Error("signature should be valid")
	}
}

// func TestUnwrapKeyset(t *testing.T) {
// 	kek, err := GetKEK(keyURI, true)
// 	if err != nil {
// 		t.Fatalf("failed to get KEK: %v", err)
// 	}

// 	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
// 	if err != nil {
// 		t.Fatalf("failed to create keyset handle: %v", err)
// 	}

// 	dk := NewTinkDelegatedKey(kh, kek)
// 	wrappedKeyset, err := dk.WrapKeyset()
// 	if err != nil {
// 		t.Fatalf("failed to wrap keyset: %v", err)
// 	}

// 	unwrappedDK, err := UnwrapKeyset(wrappedKeyset, kek)
// 	if err != nil {
// 		t.Fatalf("failed to unwrap keyset: %v", err)
// 	}

// 	if !cmp.Equal(dk.keysetHandle.KeysetInfo(), unwrappedDK.keysetHandle.KeysetInfo(),
// 		cmpopts.IgnoreUnexported(tinkpb.KeysetInfo{})) {
// 		t.Error("unwrapped keyset doesn't match the original keyset")
// 	}
// }
