package encrypted

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
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
	// Set the table name for the query input
	input.TableName = &tableName

	// Execute the query through the EncryptedClient
	encryptedOutput, err := et.client.Query(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("error querying encrypted items: %w", err)
	}

	// The items are already decrypted by EncryptedClient.Query, return the result directly
	return encryptedOutput, nil
}

// Scan executes a Scan operation on the DynamoDB table and decrypts the returned items.
func (et *EncryptedTable) Scan(ctx context.Context, tableName string, input *dynamodb.ScanInput) (*dynamodb.ScanOutput, error) {
	// Set the table name for the scan input
	input.TableName = &tableName

	// Execute the scan through the EncryptedClient
	encryptedOutput, err := et.client.Scan(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("error scanning encrypted items: %w", err)
	}

	// The items are already decrypted by EncryptedClient. Scan, return the result directly
	return encryptedOutput, nil
}
