package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/client"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/crypto"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/provider"
)

func main() {
	// Create a new AWS session
	sess := session.Must(session.NewSession())

	// Create a DynamoDB client
	dynamodbClient := dynamodb.New(sess)

	// Create a Crypto provider
	keyURI := "aws-kms://arn:aws:kms:eu-west-2:076594877490:key/02813db0-b23a-420c-94b0-bdceb08e121b"
	cryptoProvider, err := crypto.New(keyURI)
	if err != nil {
		log.Fatal("Failed to create Crypto provider:", err)
	}

	materialsProvider := provider.NewCryptographicMaterialsProvider(cryptoProvider, map[string]string{
		"example": "example-value",
	})
	// Configure attribute actions
	attributeActions := client.NewAttributeActions().
		WithDefaultAction(crypto.Encrypt).
		WithAttributeAction("name", crypto.EncryptDeterministically)
	encryptedClient := client.NewEncryptedClient(dynamodbClient, cryptoProvider, materialsProvider, attributeActions)

	// Table name for testing
	tableName := "test"

	// Create the test table if it doesn't exist
	err = createTableIfNotExists(dynamodbClient, tableName)
	if err != nil {
		log.Fatal("Failed to create table:", err)
	}

	// Create a new item with various attribute types
	item := map[string]*dynamodb.AttributeValue{
		"id":      {S: aws.String("123")},
		"name":    {S: aws.String("John Doe")},
		"age":     {N: aws.String("30")},
		"city":    {S: aws.String("New York")},
		"active":  {BOOL: aws.Bool(true)},
		"skills":  {SS: aws.StringSlice([]string{"Go", "Python", "Java"})},
		"scores":  {NS: aws.StringSlice([]string{"85", "92", "78"})},
		"data":    {B: []byte("some binary data")},
		"created": {S: aws.String(time.Now().Format(time.RFC3339))},
		"metadata": {M: map[string]*dynamodb.AttributeValue{
			"key1": {S: aws.String("value1")},
			"key2": {N: aws.String("42")},
		}},
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

func putItem(encryptedClient *client.EncryptedClient, tableName string, item map[string]*dynamodb.AttributeValue) error {
	putItemInput := &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	}

	_, err := encryptedClient.PutItem(context.Background(), putItemInput)
	if err != nil {
		return fmt.Errorf("failed to put item: %v", err)
	}

	return nil
}

func getItem(encryptedClient *client.EncryptedClient, tableName string, id string) (map[string]*dynamodb.AttributeValue, error) {
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

	return getItemOutput.Item, nil
}

func printItem(item map[string]*dynamodb.AttributeValue) {
	for key, value := range item {
		switch {
		case value.S != nil:
			fmt.Printf("%s: %s\n", key, *value.S)
		case value.N != nil:
			fmt.Printf("%s: %s\n", key, *value.N)
		case value.BOOL != nil:
			fmt.Printf("%s: %t\n", key, *value.BOOL)
		case value.SS != nil:
			fmt.Printf("%s: %v\n", key, aws.StringValueSlice(value.SS))
		case value.NS != nil:
			fmt.Printf("%s: %v\n", key, aws.StringValueSlice(value.NS))
		case value.B != nil:
			fmt.Printf("%s: %s\n", key, string(value.B))
		case value.M != nil:
			fmt.Printf("%s:\n", key)
			for k, v := range value.M {
				fmt.Printf("  %s: %v\n", k, v)
			}
		default:
			fmt.Printf("%s: %v\n", key, value)
		}
	}
}
