package client

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/provider"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/utils"
)

// EncryptedClient facilitates encrypted operations on DynamoDB items.
type EncryptedClient struct {
	client            *dynamodb.Client
	materialsProvider provider.CryptographicMaterialsProvider
	primaryKeyInfo    *utils.PrimaryKeyInfo
	primaryKeyCache   map[string]*utils.PrimaryKeyInfo
}

// NewEncryptedClient creates a new instance of EncryptedClient.
func NewEncryptedClient(client *dynamodb.Client, materialsProvider provider.CryptographicMaterialsProvider) *EncryptedClient {
	return &EncryptedClient{
		client:            client,
		materialsProvider: materialsProvider,
		primaryKeyInfo:    nil,
		primaryKeyCache:   make(map[string]*utils.PrimaryKeyInfo),
	}
}

// PutItem encrypts an item and puts it into a DynamoDB table.
func (ec *EncryptedClient) PutItem(ctx context.Context, input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	tableName := *input.TableName

	// Cache check for primary key info
	pkInfo, ok := ec.primaryKeyCache[tableName]
	if !ok {
		var err error
		pkInfo, err = ec.getPrimaryKeyInfo(ctx, tableName)
		if err != nil {
			return nil, fmt.Errorf("error fetching primary key info: %v", err)
		}
	}
	partitionKeyValue := input.Item[pkInfo.PartitionKey].(*types.AttributeValueMemberS).Value
	var sortKeyValue string
	if pkInfo.SortKey != "" && input.Item[pkInfo.SortKey] != nil {
		sortKeyValue = input.Item[pkInfo.SortKey].(*types.AttributeValueMemberS).Value
	}

	// Construct and hash the material name
	rawMaterialName := tableName + "-" + partitionKeyValue
	if sortKeyValue != "" {
		rawMaterialName += "-" + sortKeyValue
	}

	materialName := utils.HashString(rawMaterialName)

	// Generate and store new material
	encryptionMaterials, err := ec.materialsProvider.EncryptionMaterials(context.Background(), materialName)
	if err != nil {
		log.Fatalf("Failed to generate encryption materials: %v", err)
	}

	// Create a new item map to hold encrypted attributes
	encryptedItem := make(map[string]types.AttributeValue)

	// Encrypt attribute values, excluding primary keys
	for key, value := range input.Item {
		if key == pkInfo.PartitionKey || key == pkInfo.SortKey {
			// Copy primary key attributes as is
			encryptedItem[key] = value
			continue
		}

		// Convert attribute value to bytes
		rawData, err := utils.AttributeValueToBytes(value)
		if err != nil {
			return nil, fmt.Errorf("error converting attribute value to bytes: %v", err)
		}

		// Encrypt the data
		encryptedData, err := encryptionMaterials.EncryptionKey().Encrypt(rawData, []byte(key))
		if err != nil {
			return nil, fmt.Errorf("error encrypting attribute value: %v", err)
		}

		// Store the encrypted data as a binary attribute value
		encryptedItem[key] = &types.AttributeValueMemberB{Value: encryptedData}
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

	tableName := *input.TableName

	// Cache check for primary key info
	pkInfo, ok := ec.primaryKeyCache[tableName]
	if !ok {
		var err error
		pkInfo, err = ec.getPrimaryKeyInfo(ctx, tableName)
		if err != nil {
			return nil, fmt.Errorf("error fetching primary key info: %v", err)
		}
	}
	partitionKeyValue := input.Key[pkInfo.PartitionKey].(*types.AttributeValueMemberS).Value
	var sortKeyValue string
	if pkInfo.SortKey != "" && input.Key[pkInfo.SortKey] != nil {
		sortKeyValue = input.Key[pkInfo.SortKey].(*types.AttributeValueMemberS).Value
	}

	// Construct and hash the material name
	rawMaterialName := tableName + "-" + partitionKeyValue
	if sortKeyValue != "" {
		rawMaterialName += "-" + sortKeyValue
	}

	materialName := utils.HashString(rawMaterialName)

	// Fetch decryption materials
	decryptionMaterials, err := ec.materialsProvider.DecryptionMaterials(ctx, materialName, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch decryption materials: %v", err)
	}

	// Decrypt each attribute value, excluding primary keys
	decryptedItem := make(map[string]types.AttributeValue)
	for key, value := range encryptedOutput.Item {
		if key == pkInfo.PartitionKey || key == pkInfo.SortKey {
			// Copy primary key attributes as is
			decryptedItem[key] = value
			continue
		}

		// Decrypt the data
		rawData, err := decryptionMaterials.DecryptionKey().Decrypt(value.(*types.AttributeValueMemberB).Value, []byte(key))
		if err != nil {
			return nil, fmt.Errorf("error decrypting attribute value: %v", err)
		}

		// Convert bytes back to AttributeValue
		decryptedValue, err := utils.BytesToAttributeValue(rawData)
		if err != nil {
			return nil, fmt.Errorf("error converting bytes to attribute value: %v", err)
		}

		decryptedItem[key] = decryptedValue
	}

	// Create a new GetItemOutput with the decrypted item
	decryptedOutput := &dynamodb.GetItemOutput{
		Item: decryptedItem,
	}

	return decryptedOutput, nil
}

func (ec *EncryptedClient) getPrimaryKeyInfo(ctx context.Context, tableName string) (*utils.PrimaryKeyInfo, error) {
	if ec.primaryKeyInfo != nil {
		return ec.primaryKeyInfo, nil
	}

	// Fetch the table info since it's not yet cached
	pkInfo, err := utils.TableInfo(ctx, ec.client, tableName)
	if err != nil {
		return nil, err
	}

	// Cache the table info for future use
	ec.primaryKeyInfo = pkInfo
	ec.primaryKeyCache[tableName] = pkInfo

	return pkInfo, nil
}
