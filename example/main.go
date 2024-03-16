package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/cloudopsy/dynamodb-encryption-go/internal/crypto"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/client"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/provider"
)

func main() {
	// Initialize an AWS session.
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String("eu-west-2"),
	}))

	// Create a DynamoDB client.
	dynamodbClient := dynamodb.New(sess)

	// Set up the key URI for AWS KMS.
	keyURI := "aws-kms://arn:aws:kms:eu-west-2:076594877490:key/02813db0-b23a-420c-94b0-bdceb08e121b"

	// Initialize the AWS KMS Cryptographic Materials Provider with specific options.
	materialsProvider := provider.NewsCryptographicMaterialsProvider(sess,
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
	item := map[string]*dynamodb.AttributeValue{
		"id":         {S: aws.String("001")},
		"first_name": {S: aws.String("John")},
		"last_name":  {S: aws.String("Doe")},
		"email":      {S: aws.String("johndoe@example.com")},
		"created_at": {S: aws.String(time.Now().Format(time.RFC3339))},
	}

	// Put the encrypted item into the DynamoDB table.
	_, err := encryptedClient.PutItem(context.Background(), &dynamodb.PutItemInput{
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
		Key: map[string]*dynamodb.AttributeValue{
			"id": {S: aws.String("001")},
		},
	})
	if err != nil {
		log.Fatalf("Failed to get encrypted item: %v", err)
	}
	fmt.Println("Successfully retrieved and decrypted item:", getItemOutput.Item)
}
