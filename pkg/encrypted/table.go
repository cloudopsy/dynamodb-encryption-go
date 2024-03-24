package encrypted

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go/aws"
)

// EncryptedTable provides a high-level interface to encrypted DynamoDB operations.
type EncryptedTable struct {
	client *EncryptedClient
}

// NewEncryptedTable creates a new EncryptedTable with the given EncryptedClient.
func NewEncryptedTable(client *EncryptedClient) *EncryptedTable {
	return &EncryptedTable{
		client: client,
	}
}

// PutItem encrypts and stores an item in the DynamoDB table.
func (et *EncryptedTable) PutItem(ctx context.Context, tableName string, item map[string]types.AttributeValue) error {
	putItemInput := &dynamodb.PutItemInput{
		TableName: &tableName,
		Item:      item,
	}
	_, err := et.client.PutItem(ctx, putItemInput)
	if err != nil {
		return fmt.Errorf("failed to put encrypted item: %w", err)
	}
	return nil
}

// GetItem retrieves and decrypts an item from the DynamoDB table.
func (et *EncryptedTable) GetItem(ctx context.Context, tableName string, key map[string]types.AttributeValue) (map[string]types.AttributeValue, error) {
	getItemInput := &dynamodb.GetItemInput{
		TableName: &tableName,
		Key:       key,
	}
	result, err := et.client.GetItem(ctx, getItemInput)
	if err != nil {
		return nil, fmt.Errorf("failed to get and decrypt item: %w", err)
	}
	return result.Item, nil
}

// Query executes a Query operation on the DynamoDB table and decrypts the returned items.
func (et *EncryptedTable) Query(ctx context.Context, tableName string, input *dynamodb.QueryInput) (*dynamodb.QueryOutput, error) {
	input.TableName = &tableName

	encryptedOutput, err := et.client.Query(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("error querying encrypted items: %w", err)
	}

	return encryptedOutput, nil
}

// Scan executes a Scan operation on the DynamoDB table and decrypts the returned items.
func (et *EncryptedTable) Scan(ctx context.Context, tableName string, input *dynamodb.ScanInput) (*dynamodb.ScanOutput, error) {
	input.TableName = &tableName

	encryptedOutput, err := et.client.Scan(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("error scanning encrypted items: %w", err)
	}

	return encryptedOutput, nil
}

// CreateTable creates a new DynamoDB table with the specified name, attribute definitions, and key schema.
func (et *EncryptedTable) CreateTable(ctx context.Context, tableName string, attributes []types.AttributeDefinition, keySchema []types.KeySchemaElement) error {
	input := &dynamodb.CreateTableInput{
		AttributeDefinitions: attributes,
		KeySchema:            keySchema,
		BillingMode:          types.BillingModePayPerRequest,
		TableName:            aws.String(tableName),
	}

	_, err := et.client.CreateTable(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	return nil
}
