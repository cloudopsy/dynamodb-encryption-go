package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/encrypted"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/provider"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/provider/store"
)

// Secret represents the structure of a secret stored in DynamoDB
type Secret struct {
	TenantID    string            `dynamodbav:"TenantID"`
	NameVersion string            `dynamodbav:"NameVersion"`
	Data        []byte            `dynamodbav:"Data"`
	Metadata    map[string]string `dynamodbav:"Metadata"`
	CreatedAt   int64             `dynamodbav:"CreatedAt"`
	UpdatedAt   int64             `dynamodbav:"UpdatedAt"`
	Enabled     bool              `dynamodbav:"Enabled"`
	ExpiresAt   int64             `dynamodbav:"ExpiresAt"`
}

// SecretManager manages operations on secrets
type SecretManager struct {
	encryptedTable *encrypted.EncryptedTable
}

// NewSecretManager creates a new instance of SecretManager
func NewSecretManager(et *encrypted.EncryptedTable) *SecretManager {
	return &SecretManager{
		encryptedTable: et,
	}
}

// incrementVersion is a helper function to determine the next version number for a secret
func (sm *SecretManager) incrementVersion(tenantID, secretID string) (int, error) {
	return 1, nil
}

// WriteSecret writes a new version of a secret to the database
func (sm *SecretManager) WriteSecret(ctx context.Context, tenantID, secretID string, plaintext []byte, metadata map[string]string) error {
	version, err := sm.incrementVersion(tenantID, secretID)
	if err != nil {
		return err
	}

	// Create a new secret
	secret := Secret{
		TenantID:    tenantID,
		NameVersion: fmt.Sprintf("%s#%d", secretID, version),
		Data:        plaintext,
		Metadata:    metadata,
		CreatedAt:   time.Now().Unix(),
		UpdatedAt:   time.Now().Unix(),
		Enabled:     true,
		ExpiresAt:   time.Now().Add(365 * 24 * time.Hour).Unix(), // Example: Expires in 1 year
	}

	// Convert Secret struct to map[string]types.AttributeValue for DynamoDB
	item, err := attributevalue.MarshalMap(secret)
	if err != nil {
		log.Fatalf("Failed to marshal secret: %v", err)
	}

	// Write the secret to the database using EncryptedTable
	return sm.encryptedTable.PutItem(ctx, "UserSecretsTest", item)
}

func main() {
	// Setup and initialization code as previously shown
	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	keyURI := "aws-kms://arn:aws:kms:eu-west-2:076594877490:key/02813db0-b23a-420c-94b0-bdceb08e121b"

	// Create DynamoDB client
	dynamoDBClient := dynamodb.NewFromConfig(cfg)

	// Initialize the key material store
	materialStore, err := store.NewMetaStore(dynamoDBClient, "meta")
	if err != nil {
		log.Fatalf("Failed to create key material store: %v", err)
	}

	// Ensure DynamoDB table exists
	if err := materialStore.CreateTableIfNotExists(ctx); err != nil {
		log.Fatalf("Failed to ensure DynamoDB table exists: %v", err)
	}

	// Initialize the cryptographic materials provider
	cmp, err := provider.NewAwsKmsCryptographicMaterialsProvider(keyURI, nil, materialStore)
	if err != nil {
		log.Fatalf("Failed to create cryptographic materials provider: %v", err)
	}

	clientConfig := encrypted.NewClientConfig(
		encrypted.WithDefaultEncryption(encrypted.EncryptStandard),
	)

	// Initialize EncryptedClient
	ec := encrypted.NewEncryptedClient(dynamoDBClient, cmp, clientConfig)

	// Initialize EncryptedTable and SecretManager
	et := encrypted.NewEncryptedTable(ec)

	// Define attribute definitions and key schema for the UserSecretsTest table
	attributeDefinitions := []types.AttributeDefinition{
		{
			AttributeName: aws.String("TenantID"),
			AttributeType: types.ScalarAttributeTypeS,
		},
		{
			AttributeName: aws.String("NameVersion"),
			AttributeType: types.ScalarAttributeTypeS,
		},
		// Add any other attributes used as keys in global/local secondary indexes
	}
	keySchema := []types.KeySchemaElement{
		{
			AttributeName: aws.String("TenantID"),
			KeyType:       types.KeyTypeHash,
		},
		{
			AttributeName: aws.String("NameVersion"),
			KeyType:       types.KeyTypeRange,
		},
	}

	sm := NewSecretManager(et)

	// Attempt to create the UserSecretsTest table
	_ = sm.encryptedTable.CreateTable(context.TODO(), "UserSecretsTest", attributeDefinitions, keySchema)

	// Example usage of WriteSecret
	err = sm.WriteSecret(context.TODO(), "tenant1", "secretID1", []byte("mySecretData"), map[string]string{
		"Description": "Example secret",
	})
	if err != nil {
		log.Fatalf("Failed to write secret: %v", err)
	}
	fmt.Println("Secret written successfully.")
}
