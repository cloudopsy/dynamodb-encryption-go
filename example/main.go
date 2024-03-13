package main

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/client"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/provider"
)

func main() {
	// Create a new AWS session
	sess := session.Must(session.NewSession())

	// Create a DynamoDB client
	dynamodbClient := dynamodb.New(sess)

	// Create a DynamoDB Encryption Client
	keyID := "aws-kms://arn:aws:kms:eu-west-2:076594877490:key/02813db0-b23a-420c-94b0-bdceb08e121b"
	materialsProvider := provider.NewAwsKmsCryptographicMaterialsProvider(keyID, nil, nil)
	// Configure attribute actions
	attributeActions := client.NewAttributeActions().
		WithDefaultAction(client.CryptoActionEncrypt)
		// WithAttributeAction("name", client.CryptoActionEncryptDeterministicly)
	encryptedClient := client.NewEncryptedClient(dynamodbClient, materialsProvider, attributeActions)

	// Table name for testing
	tableName := "test"

	// Create the test table if it doesn't exist
	err := createTableIfNotExists(dynamodbClient, tableName)
	if err != nil {
		log.Fatal("Failed to create table:", err)
	}

	// Create a new item
	item := map[string]interface{}{
		"id":   "123",
		"name": "John Doe",
		"age":  43,
		"city": "New York",
	}

	// Put the item into the DynamoDB table
	err = putItem(encryptedClient, tableName, item)
	if err != nil {
		log.Fatal("Failed to put item:", err)
	}

	// Get the item from the DynamoDB table
	decryptedItem, err := getItem(encryptedClient, tableName, "123")
	if err != nil {
		log.Fatal("Failed to get item:", err)
	}

	// Print the decrypted item
	fmt.Println("Decrypted item:")
	printItem(decryptedItem)
}

func createTableIfNotExists(client *dynamodb.DynamoDB, tableName string) error {
	_, err := client.DescribeTable(&dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == dynamodb.ErrCodeResourceNotFoundException {
			// Table doesn't exist, create it
			input := &dynamodb.CreateTableInput{
				TableName: aws.String(tableName),
				AttributeDefinitions: []*dynamodb.AttributeDefinition{
					{
						AttributeName: aws.String("id"),
						AttributeType: aws.String("S"),
					},
				},
				KeySchema: []*dynamodb.KeySchemaElement{
					{
						AttributeName: aws.String("id"),
						KeyType:       aws.String("HASH"),
					},
				},
				ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(1),
					WriteCapacityUnits: aws.Int64(1),
				},
			}
			_, err := client.CreateTable(input)
			if err != nil {
				return fmt.Errorf("failed to create table: %v", err)
			}
			fmt.Printf("Table %s created successfully\n", tableName)
		} else {
			return fmt.Errorf("failed to describe table: %v", err)
		}
	}
	return nil
}

func putItem(encryptedClient *client.EncryptedClient, tableName string, item map[string]interface{}) error {
	// Convert the item to DynamoDB AttributeValue map
	attributeValues, err := dynamodbattribute.MarshalMap(item)
	if err != nil {
		return fmt.Errorf("failed to marshal item: %v", err)
	}

	// Put the item into the DynamoDB table
	putItemInput := &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      attributeValues,
	}

	_, err = encryptedClient.PutItem(context.Background(), putItemInput)
	if err != nil {
		return fmt.Errorf("failed to put item: %v", err)
	}

	return nil
}

func getItem(encryptedClient *client.EncryptedClient, tableName string, id string) (map[string]interface{}, error) {
	// Get the item from the DynamoDB table
	getItemInput := &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {S: aws.String(id)},
		},
	}

	getItemOutput, err := encryptedClient.GetItem(context.Background(), getItemInput)
	if err != nil {
		return nil, fmt.Errorf("failed to get item: %v", err)
	}

	// Unmarshal the decrypted item
	var decryptedItem map[string]interface{}
	err = dynamodbattribute.UnmarshalMap(getItemOutput.Item, &decryptedItem)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal item: %v", err)
	}

	return decryptedItem, nil
}

func printItem(item map[string]interface{}) {
	for key, value := range item {
		fmt.Printf("%s: %v\n", key, value)
	}
}
