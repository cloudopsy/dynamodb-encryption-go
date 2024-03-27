package main

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
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
	db             *dynamodb.Client
	tableName      string
}

// NewSecretManager creates a new instance of SecretManager
func NewSecretManager(et *encrypted.EncryptedTable, db *dynamodb.Client, tableName string) *SecretManager {
	return &SecretManager{
		encryptedTable: et,
		db:             db,
		tableName:      tableName,
	}
}

// ReadLatestSecretVersion queries DynamoDB to find the latest version of a secret.
func (sm *SecretManager) ReadLatestSecretVersion(ctx context.Context, tenantID, secretID string) (*Secret, error) {
	// Construct the query input
	input := &dynamodb.QueryInput{
		TableName:              aws.String(sm.tableName),
		KeyConditionExpression: aws.String("TenantID = :tenantID AND begins_with(NameVersion, :name)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":tenantID": &types.AttributeValueMemberS{Value: tenantID},
			":name":     &types.AttributeValueMemberS{Value: secretID + "#"},
		},
		ScanIndexForward: aws.Bool(false),
		Limit:            aws.Int32(1),
	}

	// Execute the query
	resp, err := sm.encryptedTable.Query(ctx, sm.tableName, input)
	if err != nil {
		return nil, fmt.Errorf("failed to query latest secret version: %w", err)
	}

	// Check if a secret was returned
	if len(resp.Items) == 0 {
		return nil, nil // No versions found, return nil to indicate a new secret should start with version 1
	}

	// Unmarshal the result into a Secret struct
	var secret Secret
	err = attributevalue.UnmarshalMap(resp.Items[0], &secret)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret: %w", err)
	}

	return &secret, nil
}

// incrementVersion queries for the latest version of a secret and increments it
func (sm *SecretManager) incrementVersion(ctx context.Context, tenantID, secretID string) (int, error) {
	latestSecret, err := sm.ReadLatestSecretVersion(ctx, tenantID, secretID)
	if err != nil {
		return 0, fmt.Errorf("failed to get latest secret version: %w", err)
	}

	var version int
	if latestSecret != nil {
		// Split NameVersion to get the version part
		parts := strings.Split(latestSecret.NameVersion, "#")
		if len(parts) == 2 {
			version, err = strconv.Atoi(parts[1])
			if err != nil {
				return 0, fmt.Errorf("failed to parse version number: %w", err)
			}
			version++
		} else {
			return 0, fmt.Errorf("unexpected NameVersion format: %s", latestSecret.NameVersion)
		}
	} else {
		// If no secrets found, start with version 1
		version = 1
	}

	return version, nil
}

// WriteSecret writes a new version of a secret to the database
func (sm *SecretManager) WriteSecret(ctx context.Context, tenantID, secretID string, plaintext []byte, metadata map[string]string) error {
	version, err := sm.incrementVersion(ctx, tenantID, secretID)
	if err != nil {
		return fmt.Errorf("failed to increment version: %w", err)
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
		ExpiresAt:   time.Now().Add(365 * 24 * time.Hour).Unix(),
	}

	// Convert Secret struct to map[string]types.AttributeValue for DynamoDB
	item, err := attributevalue.MarshalMap(secret)
	if err != nil {
		return fmt.Errorf("failed to marshal secret: %w", err)
	}

	// Write the secret to the database using EncryptedTable
	return sm.encryptedTable.PutItem(ctx, sm.tableName, item)
}

func main() {
	// Setup and initialization code as previously shown
	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	tableName := "UserSecretsTest"

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
	ec := encrypted.NewEncryptedClient(dynamoDBClient, cmp, encrypted.WithClientConfig(clientConfig))

	// Initialize EncryptedTable and SecretManager
	et := encrypted.NewEncryptedTable(ec)
	sm := NewSecretManager(et, dynamoDBClient, tableName)

	// Attempt to create the UserSecretsTest table
	err = sm.encryptedTable.CreateTable(ctx, tableName, []types.AttributeDefinition{
		{
			AttributeName: aws.String("TenantID"),
			AttributeType: types.ScalarAttributeTypeS,
		},
		{
			AttributeName: aws.String("NameVersion"),
			AttributeType: types.ScalarAttributeTypeS,
		},
	}, []types.KeySchemaElement{
		{
			AttributeName: aws.String("TenantID"),
			KeyType:       types.KeyTypeHash,
		},
		{
			AttributeName: aws.String("NameVersion"),
			KeyType:       types.KeyTypeRange,
		},
	})

	if err != nil {
		fmt.Printf("Failed to create UserSecretsTest table: %v\n", err)
	}

	// Example usage of WriteSecret
	err = sm.WriteSecret(ctx, "tenant1", "secretID1", []byte("mySecretData"), map[string]string{
		"Description": "Example secret",
	})
	if err != nil {
		log.Fatalf("Failed to write secret: %v", err)
	}
	fmt.Println("Secret written successfully.")

	latestSecret, err := sm.ReadLatestSecretVersion(ctx, "tenant1", "secretID1")
	if err != nil {
		log.Fatalf("Failed to read latest secret: %v", err)
	}
	if latestSecret == nil {
		fmt.Println("No secrets found.")
	} else {
		fmt.Println(latestSecret)

	}

}
