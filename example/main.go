package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/cloudopsy/dynamodb-encryption-go/internal/crypto"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/client"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/provider"
)

func main() {
	// Initialize an AWS session.
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion("eu-west-2"))
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}

	// Create a DynamoDB client.
	dynamodbClient := dynamodb.NewFromConfig(cfg)

	// Set up the key URI for AWS KMS.
	keyURI := "aws-kms://arn:aws:kms:eu-west-2:076594877490:key/02813db0-b23a-420c-94b0-bdceb08e121b"

	// Initialize the AWS KMS Cryptographic Materials Provider with specific options.
	materialsProvider := provider.NewsCryptographicMaterialsProvider(
		crypto.WithKMS(keyURI),
		crypto.WithDefault(crypto.Encrypt),
		crypto.WithAttribute("email", crypto.EncryptDeterministically),
		crypto.WithAttribute("id", crypto.DoNothing),
	)

	// Create an encrypted DynamoDB client using the materials provider.
	encryptedClient := client.NewEncryptedClient(dynamodbClient, materialsProvider)

	// Define a DynamoDB table name.
	tableName := "test"

	// Create an example item to put into the DynamoDB table.
	item := map[string]types.AttributeValue{
		"id":         &types.AttributeValueMemberS{Value: "001"},
		"first_name": &types.AttributeValueMemberS{Value: "John"},
		"last_name":  &types.AttributeValueMemberS{Value: "Doe"},
		"email":      &types.AttributeValueMemberS{Value: "johndoe@example.com"},
		"created_at": &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)},
	}

	// Put the encrypted item into the DynamoDB table.
	_, err = encryptedClient.PutItem(context.Background(), &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	})
	if err != nil {
		log.Fatalf("Failed to put encrypted item: %v", err)
	}
	fmt.Println("Successfully put encrypted item.")

	// Retrieve the encrypted item from the DynamoDB table.
	getItemOutput, err := encryptedClient.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: "001"},
		},
	})
	if err != nil {
		log.Fatalf("Failed to get encrypted item: %v", err)
	}
	fmt.Println("Successfully retrieved and decrypted item:", getItemOutput.Item)
}
