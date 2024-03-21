package client

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/provider"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/utils"
)

// EncryptedClient facilitates encrypted operations on DynamoDB items.
type EncryptedClient struct {
	client            *dynamodb.Client
	materialsProvider provider.CryptographicMaterialsProvider
	primaryKeyCache   map[string]*utils.PrimaryKeyInfo
	lock              sync.RWMutex
}

// NewEncryptedClient creates a new instance of EncryptedClient.
func NewEncryptedClient(client *dynamodb.Client, materialsProvider provider.CryptographicMaterialsProvider) *EncryptedClient {
	return &EncryptedClient{
		client:            client,
		materialsProvider: materialsProvider,
		primaryKeyCache:   make(map[string]*utils.PrimaryKeyInfo),
		lock:              sync.RWMutex{},
	}
}

// PutItem encrypts an item and puts it into a DynamoDB table.
func (ec *EncryptedClient) PutItem(ctx context.Context, input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	// Encrypt the item, excluding primary keys
	encryptedItem, err := ec.encryptItem(ctx, *input.TableName, input.Item)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt item: %v", err)
	}

	// Create a new PutItemInput with the encrypted item
	encryptedInput := &dynamodb.PutItemInput{
		TableName: input.TableName,
		Item:      encryptedItem,
	}

	// Put the encrypted item into the DynamoDB table
	return ec.client.PutItem(ctx, encryptedInput)
}

// GetItem retrieves an item from a DynamoDB table and decrypts it.
func (ec *EncryptedClient) GetItem(ctx context.Context, input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	// First, retrieve the encrypted item from DynamoDB
	encryptedOutput, err := ec.client.GetItem(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("error retrieving encrypted item: %v", err)
	}

	// Check if item is found
	if encryptedOutput.Item == nil {
		return nil, fmt.Errorf("item not found")
	}

	// Decrypt the item, excluding primary keys
	decryptedItem, err := ec.decryptItem(ctx, *input.TableName, encryptedOutput.Item)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt item: %v", err)
	}

	// Create a new GetItemOutput with the decrypted item
	decryptedOutput := &dynamodb.GetItemOutput{
		Item: decryptedItem,
	}

	return decryptedOutput, nil
}

// Query executes a Query operation on DynamoDB and decrypts the returned items.
func (ec *EncryptedClient) Query(ctx context.Context, input *dynamodb.QueryInput) (*dynamodb.QueryOutput, error) {
	encryptedOutput, err := ec.client.Query(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("error querying encrypted items: %v", err)
	}

	// Decrypt the items in the response
	for i, item := range encryptedOutput.Items {
		decryptedItem, decryptErr := ec.decryptItem(ctx, *input.TableName, item)
		if decryptErr != nil {
			return nil, decryptErr
		}
		encryptedOutput.Items[i] = decryptedItem
	}

	return encryptedOutput, nil
}

// Scan executes a Scan operation on DynamoDB and decrypts the returned items.
func (ec *EncryptedClient) Scan(ctx context.Context, input *dynamodb.ScanInput) (*dynamodb.ScanOutput, error) {
	encryptedOutput, err := ec.client.Scan(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("error scanning encrypted items: %v", err)
	}

	// Decrypt the items in the response
	for i, item := range encryptedOutput.Items {
		decryptedItem, decryptErr := ec.decryptItem(ctx, *input.TableName, item)
		if decryptErr != nil {
			return nil, decryptErr
		}
		encryptedOutput.Items[i] = decryptedItem
	}

	return encryptedOutput, nil
}

// BatchWriteItem performs batch write operations, encrypting any items to be put.
func (ec *EncryptedClient) BatchWriteItem(ctx context.Context, input *dynamodb.BatchWriteItemInput) (*dynamodb.BatchWriteItemOutput, error) {
	// Iterate over each table's write requests
	for tableName, writeRequests := range input.RequestItems {
		for i, writeRequest := range writeRequests {
			if writeRequest.PutRequest != nil {
				// Encrypt the item for PutRequest
				encryptedItem, err := ec.encryptItem(ctx, tableName, writeRequest.PutRequest.Item)
				if err != nil {
					return nil, err
				}
				input.RequestItems[tableName][i].PutRequest.Item = encryptedItem
			}
		}
	}

	return ec.client.BatchWriteItem(ctx, input)
}

// BatchGetItem retrieves a batch of items from DynamoDB and decrypts them.
func (ec *EncryptedClient) BatchGetItem(ctx context.Context, input *dynamodb.BatchGetItemInput) (*dynamodb.BatchGetItemOutput, error) {
	encryptedOutput, err := ec.client.BatchGetItem(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("error batch getting encrypted items: %v", err)
	}

	// Decrypt the items in the response for each table
	for tableName, result := range encryptedOutput.Responses {
		for i, item := range result {
			decryptedItem, decryptErr := ec.decryptItem(ctx, tableName, item)
			if decryptErr != nil {
				return nil, decryptErr
			}
			encryptedOutput.Responses[tableName][i] = decryptedItem
		}
	}

	return encryptedOutput, nil
}

// DeleteItem deletes an item and its associated metadata from a DynamoDB table.
func (ec *EncryptedClient) DeleteItem(ctx context.Context, input *dynamodb.DeleteItemInput) (*dynamodb.DeleteItemOutput, error) {
	// First, delete the item from DynamoDB
	deleteOutput, err := ec.client.DeleteItem(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("error deleting encrypted item: %v", err)
	}

	// Determine the material name or metadata identifier
	pkInfo, err := ec.getPrimaryKeyInfo(ctx, *input.TableName)
	if err != nil {
		return nil, fmt.Errorf("error fetching primary key info: %v", err)
	}

	// Construct material name based on the primary key of the item being deleted
	materialName := ec.constructMaterialName(input.Key, pkInfo)

	// Delete the associated metadata
	tableName := ec.materialsProvider.TableName()
	queryInput := &dynamodb.QueryInput{
		TableName:              aws.String(tableName),
		KeyConditionExpression: aws.String("MaterialName = :materialName"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":materialName": &types.AttributeValueMemberS{Value: materialName},
		},
	}

	queryOutput, err := ec.client.Query(ctx, queryInput)
	if err != nil {
		return nil, fmt.Errorf("error querying for versions: %v", err)
	}

	for _, item := range queryOutput.Items {
		deleteRequest := map[string][]types.WriteRequest{
			tableName: {
				{
					DeleteRequest: &types.DeleteRequest{
						Key: map[string]types.AttributeValue{
							"MaterialName": item["MaterialName"],
							"Version":      item["Version"],
						},
					},
				},
			},
		}

		batchWriteInput := &dynamodb.BatchWriteItemInput{RequestItems: deleteRequest}
		_, err = ec.client.BatchWriteItem(ctx, batchWriteInput)
		if err != nil {
			return nil, fmt.Errorf("error deleting a version: %v", err)
		}
	}

	return deleteOutput, nil
}

// getPrimaryKeyInfo lazily loads and caches primary key information in a thread-safe manner.
func (ec *EncryptedClient) getPrimaryKeyInfo(ctx context.Context, tableName string) (*utils.PrimaryKeyInfo, error) {
	ec.lock.RLock()
	pkInfo, exists := ec.primaryKeyCache[tableName]
	ec.lock.RUnlock()

	if exists {
		return pkInfo, nil
	}

	ec.lock.Lock()
	defer ec.lock.Unlock()

	pkInfo, exists = ec.primaryKeyCache[tableName]
	if exists {
		return pkInfo, nil
	}

	pkInfo, err := utils.TableInfo(ctx, ec.client, tableName)
	if err != nil {
		return nil, err
	}

	ec.primaryKeyCache[tableName] = pkInfo

	return pkInfo, nil
}

// encryptItem encrypts a DynamoDB item's attributes, excluding primary keys.
func (ec *EncryptedClient) encryptItem(ctx context.Context, tableName string, item map[string]types.AttributeValue) (map[string]types.AttributeValue, error) {
	// Fetch primary key info to exclude these attributes from encryption
	pkInfo, err := ec.getPrimaryKeyInfo(ctx, tableName)
	if err != nil {
		return nil, err
	}

	// Generate and fetch encryption materials
	materialName := ec.constructMaterialName(item, pkInfo)
	encryptionMaterials, err := ec.materialsProvider.EncryptionMaterials(ctx, materialName)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch encryption materials: %v", err)
	}

	encryptedItem := make(map[string]types.AttributeValue)
	for key, value := range item {
		// Exclude primary keys from encryption
		if key == pkInfo.PartitionKey || key == pkInfo.SortKey {
			encryptedItem[key] = value
			continue
		}

		rawData, err := utils.AttributeValueToBytes(value)
		if err != nil {
			return nil, fmt.Errorf("error converting attribute value to bytes: %v", err)
		}

		encryptedData, err := encryptionMaterials.EncryptionKey().Encrypt(rawData, []byte(key))
		if err != nil {
			return nil, fmt.Errorf("error encrypting attribute value: %v", err)
		}

		encryptedItem[key] = &types.AttributeValueMemberB{Value: encryptedData}
	}

	return encryptedItem, nil
}

// decryptItem decrypts a DynamoDB item's attributes, excluding primary keys.
func (ec *EncryptedClient) decryptItem(ctx context.Context, tableName string, item map[string]types.AttributeValue) (map[string]types.AttributeValue, error) {
	pkInfo, err := ec.getPrimaryKeyInfo(ctx, tableName)
	if err != nil {
		return nil, err
	}

	// Construct the material name based on primary keys
	materialName := ec.constructMaterialName(item, pkInfo)
	decryptionMaterials, err := ec.materialsProvider.DecryptionMaterials(ctx, materialName, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch decryption materials: %v", err)
	}

	decryptedItem := make(map[string]types.AttributeValue)
	for key, value := range item {
		// Copy primary key attributes as is
		if key == pkInfo.PartitionKey || key == pkInfo.SortKey {
			decryptedItem[key] = value
			continue
		}

		encryptedData, ok := value.(*types.AttributeValueMemberB)
		if !ok {
			return nil, fmt.Errorf("expected binary data for encrypted attribute value")
		}

		rawData, err := decryptionMaterials.DecryptionKey().Decrypt(encryptedData.Value, []byte(key))
		if err != nil {
			return nil, fmt.Errorf("error decrypting attribute value: %v", err)
		}

		decryptedValue, err := utils.BytesToAttributeValue(rawData)
		if err != nil {
			return nil, fmt.Errorf("error converting bytes to attribute value: %v", err)
		}

		decryptedItem[key] = decryptedValue
	}

	return decryptedItem, nil
}

// constructMaterialName constructs a material name based on an item's primary key.
func (ec *EncryptedClient) constructMaterialName(item map[string]types.AttributeValue, pkInfo *utils.PrimaryKeyInfo) string {
	partitionKeyValue := item[pkInfo.PartitionKey].(*types.AttributeValueMemberS).Value
	sortKeyValue := ""
	if pkInfo.SortKey != "" && item[pkInfo.SortKey] != nil {
		sortKeyValue = item[pkInfo.SortKey].(*types.AttributeValueMemberS).Value
	}

	rawMaterialName := pkInfo.Table + "-" + partitionKeyValue
	if sortKeyValue != "" {
		rawMaterialName += "-" + sortKeyValue
	}

	return utils.HashString(rawMaterialName)
}
