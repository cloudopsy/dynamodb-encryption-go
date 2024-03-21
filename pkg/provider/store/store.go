package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/materials"
)

type KeyMaterialStore struct {
	DynamoDBClient *dynamodb.Client
	TableName      string
}

// NewKeyMaterialStore creates a new instance of KeyMaterialStore.
func NewKeyMaterialStore(dynamoDBClient *dynamodb.Client, tableName string) (*KeyMaterialStore, error) {
	return &KeyMaterialStore{
		DynamoDBClient: dynamoDBClient,
		TableName:      tableName,
	}, nil
}

// StoreNewMaterial stores a new material along with its encryption context serialized as JSON.
func (s *KeyMaterialStore) StoreNewMaterial(ctx context.Context, materialName string, material *materials.EncryptionMaterials) error {
	// Serialize the material description to a JSON string.
	materialDescriptionJSON, err := json.Marshal(material.MaterialDescription())
	if err != nil {
		return fmt.Errorf("failed to serialize material description: %v", err)
	}

	// Start a transaction to ensure atomic increment of version
	transactItems := []types.TransactWriteItem{}

	// Placeholder for the new version number
	var newVersion int64 = 1 // default to 1 if no existing versions

	// Attempt to fetch the latest version of the material
	currentVersion, err := s.getLastVersion(ctx, materialName)
	if err != nil {
		return err
	}
	if currentVersion != 0 {
		newVersion = currentVersion + 1
	}

	// Conditional check to ensure the version has not been updated since it was last fetched
	conditionExpression := "attribute_not_exists(Version) OR Version < :newVersion"
	expressionAttributeValues := map[string]types.AttributeValue{
		":newVersion": &types.AttributeValueMemberN{Value: strconv.FormatInt(newVersion, 10)},
	}

	// Prepare the new material item with the incremented version
	item := map[string]types.AttributeValue{
		"MaterialName":        &types.AttributeValueMemberS{Value: materialName},
		"Version":             &types.AttributeValueMemberN{Value: strconv.FormatInt(newVersion, 10)},
		"MaterialDescription": &types.AttributeValueMemberS{Value: string(materialDescriptionJSON)},
	}

	putItem := types.TransactWriteItem{
		Put: &types.Put{
			TableName:                 aws.String(s.TableName),
			Item:                      item,
			ConditionExpression:       aws.String(conditionExpression),
			ExpressionAttributeValues: expressionAttributeValues,
		},
	}
	transactItems = append(transactItems, putItem)

	// Execute the transaction
	_, err = s.DynamoDBClient.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: transactItems,
	})
	if err != nil {
		return fmt.Errorf("transaction failed: %v", err)
	}

	return nil
}

// RetrieveMaterial retrieves a material and its encryption context by materialName and version.
func (s *KeyMaterialStore) RetrieveMaterial(ctx context.Context, materialName string, version int64) (map[string]string, string, error) {
	// If version is less than 1, retrieve the latest version
	if version < 1 {
		var err error
		version, err = s.getLastVersion(ctx, materialName)
		if err != nil {
			return nil, "", err
		}
	}

	input := &dynamodb.GetItemInput{
		TableName: &s.TableName,
		Key: map[string]types.AttributeValue{
			"MaterialName": &types.AttributeValueMemberS{Value: materialName},
			"Version":      &types.AttributeValueMemberN{Value: strconv.FormatInt(version, 10)},
		},
	}

	// Execute the get item request.
	result, err := s.DynamoDBClient.GetItem(ctx, input)
	if err != nil {
		return nil, "", err
	}

	// Check if the item was found.
	if result.Item == nil {
		return nil, "", fmt.Errorf("material not found")
	}

	// Directly use the MaterialDescription attribute as a JSON string.
	materialDescriptionAttr, ok := result.Item["MaterialDescription"].(*types.AttributeValueMemberS)
	if !ok {
		return nil, "", fmt.Errorf("unexpected type for MaterialDescription attribute")
	}
	materialDescriptionJSON := materialDescriptionAttr.Value

	// Deserialize the JSON string back into a map[string]string.
	var materialDescMap map[string]string
	err = json.Unmarshal([]byte(materialDescriptionJSON), &materialDescMap)
	if err != nil {
		return nil, "", fmt.Errorf("failed to deserialize material description: %v", err)
	}

	// Extract the WrappedKeyset from the material description if present
	wrappedKeysetBase64, exists := materialDescMap["WrappedKeyset"]
	if !exists {
		return nil, "", fmt.Errorf("wrapped keyset not found in material description")
	}

	return materialDescMap, wrappedKeysetBase64, nil
}

func (s *KeyMaterialStore) getLastVersion(ctx context.Context, materialName string) (int64, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(s.TableName),
		KeyConditionExpression: aws.String("MaterialName = :materialName"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":materialName": &types.AttributeValueMemberS{Value: materialName},
		},
		ScanIndexForward: aws.Bool(false),
		Limit:            aws.Int32(1),
	}

	result, err := s.DynamoDBClient.Query(ctx, input)
	if err != nil {
		return 0, err
	}

	// If no items are returned, this is the first version for the material name
	if len(result.Items) == 0 {
		return 0, nil
	}

	// Extract the version number from the result
	versionAttr, ok := result.Items[0]["Version"].(*types.AttributeValueMemberN)
	if !ok {
		return 0, fmt.Errorf("unexpected type for Version attribute")
	}

	highestVersion, err := strconv.ParseInt(versionAttr.Value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse version number: %v", err)
	}

	return highestVersion, nil

}

// CreateTableIfNotExists checks if a DynamoDB table exists, and if not, creates it.
func (s *KeyMaterialStore) CreateTableIfNotExists(ctx context.Context) error {
	_, err := s.DynamoDBClient.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(s.TableName),
	})

	// If no error, table exists, return.
	if err == nil {
		fmt.Println("Table already exists:", s.TableName)
		return nil
	}

	_, err = s.DynamoDBClient.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: aws.String(s.TableName),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("MaterialName"),
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String("Version"),
				AttributeType: types.ScalarAttributeTypeN,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("MaterialName"),
				KeyType:       types.KeyTypeHash, // Partition key
			},
			{
				AttributeName: aws.String("Version"),
				KeyType:       types.KeyTypeRange, // Sort key
			},
		},
		ProvisionedThroughput: &types.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(5),
			WriteCapacityUnits: aws.Int64(5),
		},
	})

	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	fmt.Println("Table created successfully:", s.TableName)
	return nil
}
