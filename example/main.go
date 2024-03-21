package main

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/client"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/provider"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/provider/store"
)

const (
	awsRegion         = "eu-west-2"
	keyURI            = "aws-kms://arn:aws:kms:eu-west-2:076594877490:key/02813db0-b23a-420c-94b0-bdceb08e121b"
	dynamoDBTableName = "meta"
)

func main() {
	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	// Create DynamoDB client
	dynamoDBClient := dynamodb.NewFromConfig(cfg)

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
	cmp, err := provider.NewAwsKmsCryptographicMaterialsProvider(keyURI, nil, materialStore)
	if err != nil {
		log.Fatalf("Failed to create cryptographic materials provider: %v", err)
	}

	// Initialize EncryptedClient
	ec := client.NewEncryptedClient(dynamoDBClient, cmp)

	// User credentials to encrypt and store
	userID := "user1"
	credentials := map[string]types.AttributeValue{
		"UserID":   &types.AttributeValueMemberS{Value: userID},
		"Username": &types.AttributeValueMemberS{Value: "exampleUser"},
		"Password": &types.AttributeValueMemberS{Value: "examplePassword123"},
	}

	// DynamoDB table name
	tableName := "UserCredentials"

	// Attempt to create the table
	if err := createTableIfNotExists(ctx, dynamoDBClient, tableName); err != nil {
		log.Fatalf("Error creating table: %v", err)
	}

	// Put encrypted item
	putItemInput := &dynamodb.PutItemInput{
		TableName: &tableName,
		Item:      credentials,
	}

	_, err = ec.PutItem(ctx, putItemInput)
	if err != nil {
		log.Fatalf("Failed to put encrypted item: %v", err)
	}
	fmt.Println("Encrypted item put successfully.")

	// Get and decrypt item
	getItemInput := &dynamodb.GetItemInput{
		TableName: &tableName,
		Key: map[string]types.AttributeValue{
			"UserID": &types.AttributeValueMemberS{Value: userID},
		},
	}

	result, err := ec.GetItem(ctx, getItemInput)
	if err != nil {
		log.Fatalf("Failed to get and decrypt item: %v", err)
	}

	fmt.Printf("Decrypted item: %v\n", result.Item)
}

func createTableIfNotExists(ctx context.Context, client *dynamodb.Client, tableName string) error {
	_, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})

	// If DescribeTable succeeds, the table exists and we return nil.
	if err == nil {
		fmt.Println("Table already exists:", tableName)
		return nil
	}

	// If the table does not exist, create it.
	_, err = client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: aws.String(tableName),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("UserID"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("UserID"),
				KeyType:       types.KeyTypeHash,
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	})

	if err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}

	fmt.Println("Table created successfully:", tableName)
	return nil
}
