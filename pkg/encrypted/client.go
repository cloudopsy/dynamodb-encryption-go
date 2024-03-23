package encrypted

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

type DynamoDBClientInterface interface {
	PutItem(ctx context.Context, input *dynamodb.PutItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	GetItem(ctx context.Context, input *dynamodb.GetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	Query(ctx context.Context, input *dynamodb.QueryInput, opts ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	Scan(ctx context.Context, input *dynamodb.ScanInput, opts ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error)
	BatchGetItem(ctx context.Context, input *dynamodb.BatchGetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error)
	BatchWriteItem(ctx context.Context, input *dynamodb.BatchWriteItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.BatchWriteItemOutput, error)
	DeleteItem(ctx context.Context, input *dynamodb.DeleteItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	DescribeTable(ctx context.Context, input *dynamodb.DescribeTableInput, opts ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
}

// PrimaryKeyInfo holds information about the primary key of a DynamoDB table.
type PrimaryKeyInfo struct {
	Table        string
	PartitionKey string
	SortKey      string
}

// EncryptedPaginator is a paginator for encrypted DynamoDB items.
type EncryptedPaginator struct {
	Client    *EncryptedClient
	NextToken map[string]types.AttributeValue
}

// NewEncryptedPaginator creates a new instance of EncryptedPaginator.
func NewEncryptedPaginator(client *EncryptedClient) *EncryptedPaginator {
	return &EncryptedPaginator{
		Client:    client,
		NextToken: nil,
	}
}

func (p *EncryptedPaginator) Query(ctx context.Context, input *dynamodb.QueryInput, fn func(*dynamodb.QueryOutput, bool) bool) error {
	for {
		if p.NextToken != nil {
			input.ExclusiveStartKey = p.NextToken
		}

		output, err := p.Client.Query(ctx, input)
		if err != nil {
			return err
		}

		lastPage := len(output.LastEvaluatedKey) == 0
		if !fn(output, lastPage) {
			break
		}

		if lastPage {
			break
		}

		p.NextToken = output.LastEvaluatedKey
	}

	return nil
}

func (p *EncryptedPaginator) Scan(ctx context.Context, input *dynamodb.ScanInput, fn func(*dynamodb.ScanOutput, bool) bool) error {
	for {
		if p.NextToken != nil {
			input.ExclusiveStartKey = p.NextToken
		}

		output, err := p.Client.Scan(ctx, input)
		if err != nil {
			return err
		}

		lastPage := len(output.LastEvaluatedKey) == 0
		if !fn(output, lastPage) {
			break
		}

		if lastPage {
			break
		}

		p.NextToken = output.LastEvaluatedKey
	}

	return nil
}

// EncryptedClient facilitates encrypted operations on DynamoDB items.
type EncryptedClient struct {
	Client            DynamoDBClientInterface
	MaterialsProvider provider.CryptographicMaterialsProvider
	PrimaryKeyCache   map[string]*PrimaryKeyInfo
	AttributeActions  *AttributeActions
	lock              sync.RWMutex
}

// NewEncryptedClient creates a new instance of EncryptedClient.
func NewEncryptedClient(client DynamoDBClientInterface, materialsProvider provider.CryptographicMaterialsProvider, attributeActions *AttributeActions) *EncryptedClient {
	return &EncryptedClient{
		Client:            client,
		MaterialsProvider: materialsProvider,
		PrimaryKeyCache:   make(map[string]*PrimaryKeyInfo),
		AttributeActions:  attributeActions,
		lock:              sync.RWMutex{},
	}
}

func (ec *EncryptedClient) GetPaginator(operationName string) (*EncryptedPaginator, error) {
	if operationName != "Query" && operationName != "Scan" {
		return nil, fmt.Errorf("unsupported operation for pagination: %s", operationName)
	}
	return NewEncryptedPaginator(ec), nil
}

// PutItem encrypts an item and puts it into a DynamoDB table.
func (ec *EncryptedClient) PutItem(ctx context.Context, input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	// Encrypt the item, excluding primary keys
	encryptedItem, err := ec.encryptItem(ctx, aws.StringValue(input.TableName), input.Item)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt item: %v", err)
	}

	// Create a new PutItemInput with the encrypted item
	encryptedInput := &dynamodb.PutItemInput{
		TableName: input.TableName,
		Item:      encryptedItem,
	}

	// Put the encrypted item into the DynamoDB table
	return ec.Client.PutItem(ctx, encryptedInput)
}

// GetItem retrieves an item from a DynamoDB table and decrypts it.
func (ec *EncryptedClient) GetItem(ctx context.Context, input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	// First, retrieve the encrypted item from DynamoDB
	encryptedOutput, err := ec.Client.GetItem(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("error retrieving encrypted item: %v", err)
	}

	// Check if item is found
	if encryptedOutput.Item == nil {
		return nil, fmt.Errorf("item not found")
	}

	// Decrypt the item, excluding primary keys
	decryptedItem, err := ec.decryptItem(ctx, aws.StringValue(input.TableName), encryptedOutput.Item)
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
	encryptedOutput, err := ec.Client.Query(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("error querying encrypted items: %v", err)
	}

	// Decrypt the items in the response
	for i, item := range encryptedOutput.Items {
		decryptedItem, decryptErr := ec.decryptItem(ctx, aws.StringValue(input.TableName), item)
		if decryptErr != nil {
			return nil, decryptErr
		}
		encryptedOutput.Items[i] = decryptedItem
	}

	return encryptedOutput, nil
}

// Scan executes a Scan operation on DynamoDB and decrypts the returned items.
func (ec *EncryptedClient) Scan(ctx context.Context, input *dynamodb.ScanInput) (*dynamodb.ScanOutput, error) {
	encryptedOutput, err := ec.Client.Scan(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("error scanning encrypted items: %v", err)
	}

	// Decrypt the items in the response
	for i, item := range encryptedOutput.Items {
		decryptedItem, decryptErr := ec.decryptItem(ctx, aws.StringValue(input.TableName), item)
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

	return ec.Client.BatchWriteItem(ctx, input)
}

// BatchGetItem retrieves a batch of items from DynamoDB and decrypts them.
func (ec *EncryptedClient) BatchGetItem(ctx context.Context, input *dynamodb.BatchGetItemInput) (*dynamodb.BatchGetItemOutput, error) {
	encryptedOutput, err := ec.Client.BatchGetItem(ctx, input)
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
	deleteOutput, err := ec.Client.DeleteItem(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("error deleting encrypted item: %v", err)
	}

	// Determine the material name or metadata identifier
	pkInfo, err := ec.getPrimaryKeyInfo(ctx, aws.StringValue(input.TableName))
	if err != nil {
		return nil, fmt.Errorf("error fetching primary key info: %v", err)
	}

	// Construct material name based on the primary key of the item being deleted
	materialName, err := ConstructMaterialName(input.Key, pkInfo)
	if err != nil {
		return nil, fmt.Errorf("error constructing material name: %v", err)
	}

	// Delete the associated metadata
	tableName := ec.MaterialsProvider.TableName()
	queryInput := &dynamodb.QueryInput{
		TableName:              aws.String(tableName),
		KeyConditionExpression: aws.String("MaterialName = :materialName"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":materialName": &types.AttributeValueMemberS{Value: materialName},
		},
	}

	queryOutput, err := ec.Client.Query(ctx, queryInput)
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
		_, err = ec.Client.BatchWriteItem(ctx, batchWriteInput)
		if err != nil {
			return nil, fmt.Errorf("error deleting a version: %v", err)
		}
	}

	return deleteOutput, nil
}

// getPrimaryKeyInfo lazily loads and caches primary key information in a thread-safe manner.
func (ec *EncryptedClient) getPrimaryKeyInfo(ctx context.Context, tableName string) (*PrimaryKeyInfo, error) {
	ec.lock.RLock()
	pkInfo, exists := ec.PrimaryKeyCache[tableName]
	ec.lock.RUnlock()

	if exists {
		return pkInfo, nil
	}

	ec.lock.Lock()
	defer ec.lock.Unlock()

	pkInfo, exists = ec.PrimaryKeyCache[tableName]
	if exists {
		return pkInfo, nil
	}

	pkInfo, err := TableInfo(ctx, ec.Client, tableName)
	if err != nil {
		return nil, err
	}

	ec.PrimaryKeyCache[tableName] = pkInfo

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
	materialName, err := ConstructMaterialName(item, pkInfo)
	if err != nil {
		return nil, fmt.Errorf("error constructing material name: %v", err)
	}
	encryptionMaterials, err := ec.MaterialsProvider.EncryptionMaterials(ctx, materialName)
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

		action := ec.AttributeActions.GetAttributeAction(key)
		switch action {
		case AttributeActionEncrypt, AttributeActionEncryptDeterministically:
			// TODO: Implement deterministic encryption
			encryptedData, err := encryptionMaterials.EncryptionKey().Encrypt(rawData, []byte(key))
			if err != nil {
				return nil, fmt.Errorf("error encrypting attribute value: %v", err)
			}
			encryptedItem[key] = &types.AttributeValueMemberB{Value: encryptedData}
		case AttributeActionDoNothing:
			encryptedItem[key] = value
		}
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
	materialName, err := ConstructMaterialName(item, pkInfo)
	if err != nil {
		return nil, fmt.Errorf("error constructing material name: %v", err)
	}
	decryptionMaterials, err := ec.MaterialsProvider.DecryptionMaterials(ctx, materialName, 0)
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
			// If the attribute is not encrypted, copy it as is
			decryptedItem[key] = value
			continue
		}

		action := ec.AttributeActions.GetAttributeAction(key)
		switch action {
		case AttributeActionEncrypt, AttributeActionEncryptDeterministically:
			// TODO: Implement deterministic encryption
			rawData, err := decryptionMaterials.DecryptionKey().Decrypt(encryptedData.Value, []byte(key))
			if err != nil {
				return nil, fmt.Errorf("error decrypting attribute value: %v", err)
			}
			decryptedValue, err := utils.BytesToAttributeValue(rawData)
			if err != nil {
				return nil, fmt.Errorf("error converting bytes to attribute value: %v", err)
			}

			decryptedItem[key] = decryptedValue
		case AttributeActionDoNothing:
			decryptedItem[key] = value
		}

	}

	return decryptedItem, nil
}

// TableInfo fetches the primary key names of a DynamoDB table.
func TableInfo(ctx context.Context, client DynamoDBClientInterface, tableName string) (*PrimaryKeyInfo, error) {
	resp, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe table: %w", err)
	}

	pkInfo := &PrimaryKeyInfo{}
	pkInfo.Table = tableName

	for _, keySchema := range resp.Table.KeySchema {
		if keySchema.KeyType == "HASH" {
			pkInfo.PartitionKey = *keySchema.AttributeName
		} else if keySchema.KeyType == "RANGE" {
			pkInfo.SortKey = *keySchema.AttributeName
		}
	}

	if pkInfo.PartitionKey == "" {
		return nil, fmt.Errorf("partition key not found for table: %s", tableName)
	}

	return pkInfo, nil
}

// ConstructMaterialName constructs a material name based on an item's primary key.
func ConstructMaterialName(item map[string]types.AttributeValue, pkInfo *PrimaryKeyInfo) (string, error) {
	partitionKeyValue, err := utils.AttributeValueToString(item[pkInfo.PartitionKey])
	if err != nil {
		return "", fmt.Errorf("invalid partition key attribute type: %v", err)
	}

	sortKeyValue := ""
	if pkInfo.SortKey != "" {
		sortKeyValue, err = utils.AttributeValueToString(item[pkInfo.SortKey])
		if err != nil {
			return "", fmt.Errorf("invalid sort key attribute type: %v", err)
		}
	}

	rawMaterialName := pkInfo.Table + "-" + partitionKeyValue
	if sortKeyValue != "" {
		rawMaterialName += "-" + sortKeyValue
	}

	return utils.HashString(rawMaterialName), nil
}