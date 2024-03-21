package main

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/provider"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/provider/store"
)

const (
	awsRegion         = "eu-west-2"
	keyURI            = "aws-kms://arn:aws:kms:eu-west-2:076594877490:key/02813db0-b23a-420c-94b0-bdceb08e121b"
	dynamoDBTableName = "meta"
	materialName      = "/project/password"
)

func main() {
	ctx := context.TODO()
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion))
	if err != nil {
		log.Fatalf("Failed to load AWS configuration: %v", err)
	}

	dynamoDBClient := dynamodb.NewFromConfig(awsCfg)

	// Initialize the key material store
	materialStore, err := store.NewKeyMaterialStore(dynamoDBClient, dynamoDBTableName)
	if err != nil {
		log.Fatalf("Failed to create key material store: %v", err)
	}

	// Ensure DynamoDB table exists
	if err := materialStore.CreateTableIfNotExists(ctx); err != nil {
		log.Fatalf("Failed to ensure DynamoDB table exists: %v", err)
	}

	// Initialize the cryptographic materials provider
	cmp, err := provider.NewAwsKmsCryptographicMaterialsProvider(keyURI, awsRegion, nil, materialStore)
	if err != nil {
		log.Fatalf("Failed to create cryptographic materials provider: %v", err)
	}

	// Generate and store new material
	encryptionMaterials, err := cmp.EncryptionMaterials(context.Background(), materialName)
	if err != nil {
		log.Fatalf("Failed to generate encryption materials: %v", err)
	}

	// Encrypt a message
	sampleMessage := []byte("Hello, world!")
	ciphertext, err := encryptionMaterials.EncryptionKey().Encrypt(sampleMessage, nil)
	if err != nil {
		log.Fatalf("Failed to encrypt message: %v", err)
	}
	fmt.Printf("Encrypted message: %x\n", ciphertext)

	decryptionMaterials, err := cmp.DecryptionMaterials(context.Background(), materialName, 0)
	if err != nil {
		log.Fatalf("Failed to generate decryption materials: %v", err)
	}
	fmt.Println(decryptionMaterials.DecryptionKey().Algorithm())

	// Decrypt the message
	plaintext, err := decryptionMaterials.DecryptionKey().Decrypt(ciphertext, nil)
	if err != nil {
		log.Fatalf("Failed to decrypt message: %v", err)
	}
	fmt.Printf("Decrypted message: %s\n", string(plaintext))
}
