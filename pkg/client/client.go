package client

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/provider"
)

// TableKeySchema stores the schema for DynamoDB table keys.
type TableKeySchema struct {
	PartitionKey string
	SortKey      string
}

// EncryptedClient facilitates encrypted operations on DynamoDB items.
type EncryptedClient struct {
	client            DynamoDBAPI
	materialsProvider provider.CryptographicMaterialsProvider
	tableKeySchemas   map[string]TableKeySchema
}

type DynamoDBAPI interface {
	PutItemWithContext(aws.Context, *dynamodb.PutItemInput, ...request.Option) (*dynamodb.PutItemOutput, error)
	GetItemWithContext(aws.Context, *dynamodb.GetItemInput, ...request.Option) (*dynamodb.GetItemOutput, error)
}

// NewEncryptedClient creates a new instance of EncryptedClient.
func NewEncryptedClient(client DynamoDBAPI, materialsProvider provider.CryptographicMaterialsProvider) *EncryptedClient {
	return &EncryptedClient{
		client:            client,
		materialsProvider: materialsProvider,
		tableKeySchemas:   make(map[string]TableKeySchema),
	}
}

// PutItem encrypts an item and puts it into a DynamoDB table.
func (ec *EncryptedClient) PutItem(ctx context.Context, input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	// Create a copy of the original item map to avoid modifying it during encryption
	originalItem := make(map[string]*dynamodb.AttributeValue)
	for k, v := range input.Item {
		originalItem[k] = v
	}

	encryptionMaterials, err := ec.materialsProvider.EncryptionMaterials(ctx, originalItem)
	if err != nil {
		return nil, fmt.Errorf("generating encryption materials: %v", err)
	}

	// Encrypt attributes using a copy of the item to preserve the original encryption context.
	encryptedItem, err := ec.encryptAttributes(ctx, originalItem)
	if err != nil {
		return nil, fmt.Errorf("encrypting attributes: %v", err)
	}

	for k, v := range encryptionMaterials {
		encryptedItem[k] = v
	}

	input.Item = encryptedItem

	return ec.client.PutItemWithContext(ctx, input)
}

// GetItem retrieves an item from a DynamoDB table and decrypts it.
func (ec *EncryptedClient) GetItem(ctx context.Context, input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	output, err := ec.client.GetItemWithContext(ctx, input)
	if err != nil {
		return nil, err
	}

	// Generate decryption materials using the extracted encryption context.
	_, err = ec.materialsProvider.DecryptionMaterials(ctx, output.Item)
	if err != nil {
		return nil, fmt.Errorf("generating decryption materials: %v", err)
	}

	// Decrypt attributes using the decryption materials.
	decryptedItem, err := ec.decryptAttributes(ctx, output.Item)
	if err != nil {
		return nil, fmt.Errorf("decrypting attributes: %v", err)
	}

	output.Item = decryptedItem

	return output, nil
}

func (ec *EncryptedClient) encryptAttributes(ctx context.Context, item map[string]*dynamodb.AttributeValue) (map[string]*dynamodb.AttributeValue, error) {
	encryptedItem := make(map[string]*dynamodb.AttributeValue)

	for attributeName, attributeValue := range item {
		encryptedAttributeValue, err := ec.materialsProvider.EncryptAttribute(ctx, attributeName, attributeValue)
		if err != nil {
			return nil, fmt.Errorf("encrypting attribute '%s': %v", attributeName, err)
		}
		encryptedItem[attributeName] = encryptedAttributeValue
	}

	return encryptedItem, nil
}

func (ec *EncryptedClient) decryptAttributes(ctx context.Context, item map[string]*dynamodb.AttributeValue) (map[string]*dynamodb.AttributeValue, error) {
	decryptedItem := make(map[string]*dynamodb.AttributeValue)

	for attributeName, attributeValue := range item {
		decryptedAttributeValue, err := ec.materialsProvider.DecryptAttribute(ctx, attributeName, attributeValue)
		if err != nil {
			return nil, fmt.Errorf("decrypting attribute '%s': %v", attributeName, err)
		}
		decryptedItem[attributeName] = decryptedAttributeValue
	}

	return decryptedItem, nil
}
