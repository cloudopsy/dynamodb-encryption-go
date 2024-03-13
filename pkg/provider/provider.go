// provider.go
package provider

import (
	"context"
	"fmt"

	"github.com/tink-crypto/tink-go-awskms/integration/awskms"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/daead"
	"github.com/tink-crypto/tink-go/v2/keyset"

	"github.com/cloudopsy/dynamodb-encryption-go/pkg/crypto"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/materials"
)

const WrappedDataKeyAttrName = "__wrapped_data_key"

type CryptographicMaterialsProvider interface {
	EncryptionMaterials(ctx context.Context, encryptionContext map[string]string) (*materials.EncryptionMaterials, error)
	DecryptionMaterials(ctx context.Context, encryptionContext map[string]string) (*materials.DecryptionMaterials, error)
}

type AwsKmsCryptographicMaterialsProvider struct {
	keyID               string
	grantTokens         []string
	materialDescription map[string]string
}

func NewAwsKmsCryptographicMaterialsProvider(keyID string, grantTokens []string, materialDescription map[string]string) *AwsKmsCryptographicMaterialsProvider {
	return &AwsKmsCryptographicMaterialsProvider{
		keyID:               keyID,
		grantTokens:         grantTokens,
		materialDescription: materialDescription,
	}
}

func (p *AwsKmsCryptographicMaterialsProvider) EncryptionMaterials(ctx context.Context, encryptionContext map[string]string) (*materials.EncryptionMaterials, error) {
	_, encryptedDataKey, err := crypto.GenerateDataKey(p.keyID, encryptionContext)
	if err != nil {
		return nil, fmt.Errorf("failed to generate data key: %v", err)
	}

	client, err := awskms.NewClientWithOptions(p.keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS KMS client: %v", err)
	}

	kekAEAD, err := client.GetAEAD(p.keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get AEAD primitive: %v", err)
	}

	encryptionKey := aead.NewKMSEnvelopeAEAD2(aead.AES256GCMKeyTemplate(), kekAEAD)

	description := make(map[string]string)
	for k, v := range p.materialDescription {
		description[k] = v
	}
	description[WrappedDataKeyAttrName] = crypto.EncodeBase64(encryptedDataKey)

	deterministicAEADKeyHandle, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
	if err != nil {
		return nil, fmt.Errorf("failed to create deterministic AEAD key handle: %v", err)
	}
	deterministicAEADKey, err := daead.New(deterministicAEADKeyHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to create deterministic AEAD primitive: %v", err)
	}

	return &materials.EncryptionMaterials{
		EncryptionKey:        encryptionKey,
		DeterministicAEADKey: deterministicAEADKey,
		Description:          description,
	}, nil
}

func (p *AwsKmsCryptographicMaterialsProvider) DecryptionMaterials(ctx context.Context, encryptionContext map[string]string) (*materials.DecryptionMaterials, error) {
	encryptedDataKey, err := crypto.DecodeBase64(encryptionContext[WrappedDataKeyAttrName])
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted data key: %v", err)
	}

	// Remove the wrapped data key from the encryption context
	delete(encryptionContext, WrappedDataKeyAttrName)

	_, err = crypto.DecryptDataKey(p.keyID, encryptedDataKey, encryptionContext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data key: %v", err)
	}

	client, err := awskms.NewClientWithOptions(p.keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS KMS client: %v", err)
	}

	kekAEAD, err := client.GetAEAD(p.keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get AEAD primitive: %v", err)
	}

	decryptionKey := aead.NewKMSEnvelopeAEAD2(aead.AES256GCMKeyTemplate(), kekAEAD)

	deterministicAEADKeyHandle, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
	if err != nil {
		return nil, fmt.Errorf("failed to create deterministic AEAD key handle: %v", err)
	}
	deterministicAEADKey, err := daead.New(deterministicAEADKeyHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to create deterministic AEAD primitive: %v", err)
	}

	return &materials.DecryptionMaterials{
		DecryptionKey:        decryptionKey,
		DeterministicAEADKey: deterministicAEADKey,
		Description:          encryptionContext,
	}, nil
}
