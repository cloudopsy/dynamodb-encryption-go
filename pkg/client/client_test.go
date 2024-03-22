package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/materials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockDelegatedKey struct{}

func (mk *MockDelegatedKey) Algorithm() string {
	return "MockAlgorithm"
}

func (mk *MockDelegatedKey) AllowedForRawMaterials() bool {
	return true
}

func (mk *MockDelegatedKey) Encrypt(plaintext []byte, associatedData []byte) ([]byte, error) {
	// Mock encryption: prepend "enc-" to plaintext
	return append([]byte("encrypted-"), plaintext...), nil
}

func (mk *MockDelegatedKey) Decrypt(ciphertext []byte, associatedData []byte) ([]byte, error) {
	// Attempt to interpret the ciphertext as a JSON object with an "S" key
	var decoded struct {
		S string `json:"S"`
	}

	// Decode the JSON to get the actual ciphertext
	err := json.Unmarshal(ciphertext, &decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext JSON: %v", err)
	}

	// The "real" ciphertext is assumed to be the value associated with the "S" key
	realCiphertext := decoded.S

	// Perform your mock decryption logic here. For example, removing an "encrypted-" prefix:
	if strings.HasPrefix(realCiphertext, "encrypted-") {
		decryptedValue := realCiphertext[len("encrypted-"):]
		// Return the decrypted value as a valid JSON string
		return []byte(fmt.Sprintf(`{"S":"%s"}`, decryptedValue)), nil
	}

	return nil, fmt.Errorf("invalid ciphertext")
}

func (mk *MockDelegatedKey) Sign(data []byte) ([]byte, error) {
	// Mock signing (not used in this test)
	return data, nil
}

func (mk *MockDelegatedKey) Verify(signature []byte, data []byte) (bool, error) {
	// Mock verification (not used in this test)
	return true, nil
}

func (mk *MockDelegatedKey) WrapKeyset() ([]byte, error) {
	// Mock wrapping (not used in this test)
	return []byte{}, nil
}

// MockDynamoDBClient is a mock implementation of DynamoDBClientInterface.
type MockDynamoDBClient struct {
	mock.Mock
}

func (m *MockDynamoDBClient) PutItem(ctx context.Context, input *dynamodb.PutItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	args := m.Called(ctx, input, opts)
	return args.Get(0).(*dynamodb.PutItemOutput), args.Error(1)
}

func (m *MockDynamoDBClient) GetItem(ctx context.Context, input *dynamodb.GetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	args := m.Called(ctx, input, opts)
	return args.Get(0).(*dynamodb.GetItemOutput), args.Error(1)
}

func (m *MockDynamoDBClient) Query(ctx context.Context, input *dynamodb.QueryInput, opts ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	args := m.Called(ctx, input, opts)
	return args.Get(0).(*dynamodb.QueryOutput), args.Error(1)
}

func (m *MockDynamoDBClient) Scan(ctx context.Context, input *dynamodb.ScanInput, opts ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error) {
	args := m.Called(ctx, input, opts)
	return args.Get(0).(*dynamodb.ScanOutput), args.Error(1)
}

func (m *MockDynamoDBClient) BatchGetItem(ctx context.Context, input *dynamodb.BatchGetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error) {
	args := m.Called(ctx, input, opts)
	return args.Get(0).(*dynamodb.BatchGetItemOutput), args.Error(1)
}

func (m *MockDynamoDBClient) BatchWriteItem(ctx context.Context, input *dynamodb.BatchWriteItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.BatchWriteItemOutput, error) {
	args := m.Called(ctx, input, opts)
	return args.Get(0).(*dynamodb.BatchWriteItemOutput), args.Error(1)
}

func (m *MockDynamoDBClient) DeleteItem(ctx context.Context, input *dynamodb.DeleteItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	args := m.Called(ctx, input, opts)
	return args.Get(0).(*dynamodb.DeleteItemOutput), args.Error(1)
}

func (m *MockDynamoDBClient) DescribeTable(ctx context.Context, input *dynamodb.DescribeTableInput, opts ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	args := m.Called(ctx, input, opts)
	return args.Get(0).(*dynamodb.DescribeTableOutput), args.Error(1)
}

// MockCryptographicMaterialsProvider is a mock implementation of CryptographicMaterialsProvider.
type MockCryptographicMaterialsProvider struct {
	mock.Mock
}

func (m *MockCryptographicMaterialsProvider) EncryptionMaterials(ctx context.Context, materialName string) (materials.CryptographicMaterials, error) {
	args := m.Called(ctx, materialName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*materials.EncryptionMaterials), args.Error(1)
}

func (m *MockCryptographicMaterialsProvider) DecryptionMaterials(ctx context.Context, materialName string, version int64) (materials.CryptographicMaterials, error) {
	args := m.Called(ctx, materialName, version)
	return args.Get(0).(*materials.DecryptionMaterials), args.Error(1)
}

func (m *MockCryptographicMaterialsProvider) TableName() string {
	args := m.Called()
	return args.String(0)
}

func TestEncryptedClient_PutItem(t *testing.T) {
	mockDynamoDBClient := new(MockDynamoDBClient)
	mockCMProvider := new(MockCryptographicMaterialsProvider)

	// Mocking the DescribeTable call to simulate existing table schema.
	mockDynamoDBClient.On("DescribeTable", mock.Anything, mock.Anything, mock.Anything).Return(&dynamodb.DescribeTableOutput{
		Table: &types.TableDescription{
			KeySchema: []types.KeySchemaElement{
				{AttributeName: aws.String("PK"), KeyType: types.KeyTypeHash},
				{AttributeName: aws.String("SK"), KeyType: types.KeyTypeRange},
			},
		},
	}, nil)
	mockDynamoDBClient.On("PutItem", mock.Anything, mock.Anything, mock.Anything).Return(&dynamodb.PutItemOutput{}, nil)

	// Mock the TableName call if your implementation requires it.
	mockCMProvider.On("TableName").Return("materials-table").Maybe()

	mockCMProvider.On("EncryptionMaterials", mock.Anything, mock.Anything).Return(materials.NewEncryptionMaterials(
		map[string]string{"mock": "data"},
		&MockDelegatedKey{},
		nil,
	), nil)

	encryptedClient := NewEncryptedClient(mockDynamoDBClient, mockCMProvider)

	item := map[string]types.AttributeValue{
		"PK":         &types.AttributeValueMemberS{Value: "123"},
		"SK":         &types.AttributeValueMemberS{Value: "456"},
		"Attribute1": &types.AttributeValueMemberS{Value: "Value1"},
		"Attribute2": &types.AttributeValueMemberN{Value: "100"},
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String("test-table"),
		Item:      item,
	}

	_, err := encryptedClient.PutItem(context.Background(), input)

	assert.NoError(t, err)
	mockDynamoDBClient.AssertExpectations(t)
	mockCMProvider.AssertExpectations(t)
}

func TestEncryptedClient_PutItem_Failure(t *testing.T) {
	mockDynamoDBClient := new(MockDynamoDBClient)
	mockCMProvider := new(MockCryptographicMaterialsProvider)
	encryptedClient := NewEncryptedClient(mockDynamoDBClient, mockCMProvider)

	// Mock the DescribeTable call to simulate fetching table primary key schema.
	mockDynamoDBClient.On("DescribeTable", mock.Anything, mock.AnythingOfType("*dynamodb.DescribeTableInput"), mock.Anything).Return(&dynamodb.DescribeTableOutput{
		Table: &types.TableDescription{
			KeySchema: []types.KeySchemaElement{
				{AttributeName: aws.String("PK"), KeyType: types.KeyTypeHash},
				{AttributeName: aws.String("SK"), KeyType: types.KeyTypeRange},
			},
		},
	}, nil)

	// Mock the TableName call if your implementation requires it.
	mockCMProvider.On("TableName").Return("materials-table").Maybe()

	mockCMProvider.On("EncryptionMaterials", mock.Anything, mock.Anything).Return(materials.NewEncryptionMaterials(
		map[string]string{"mock": "data"},
		&MockDelegatedKey{},
		nil,
	), nil)

	// Simulate a failure in PutItem operation
	mockDynamoDBClient.On("PutItem", mock.Anything, mock.AnythingOfType("*dynamodb.PutItemInput"), mock.Anything).Return(&dynamodb.PutItemOutput{}, fmt.Errorf("failed to put item"))

	// Attempt to put an item, expecting failure
	_, err := encryptedClient.PutItem(context.Background(), &dynamodb.PutItemInput{
		TableName: aws.String("test-table"),
		Item: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "123"},
			"SK": &types.AttributeValueMemberS{Value: "TestFailure"},
		},
	})

	// Check if error was as expected
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to put item")
	mockDynamoDBClient.AssertExpectations(t)
	mockCMProvider.AssertExpectations(t)
}

func TestEncryptedClient_GetItem_Success(t *testing.T) {
	mockDynamoDBClient := new(MockDynamoDBClient)
	mockCMProvider := new(MockCryptographicMaterialsProvider)
	encryptedClient := NewEncryptedClient(mockDynamoDBClient, mockCMProvider)

	// Mock DescribeTable call to simulate fetching table primary key schema.
	mockDynamoDBClient.On("DescribeTable", mock.Anything, mock.AnythingOfType("*dynamodb.DescribeTableInput"), mock.Anything).Return(&dynamodb.DescribeTableOutput{
		Table: &types.TableDescription{
			KeySchema: []types.KeySchemaElement{
				{AttributeName: aws.String("PK"), KeyType: types.KeyTypeHash},
				{AttributeName: aws.String("SK"), KeyType: types.KeyTypeRange},
			},
		},
	}, nil)

	// Mock GetItem call to return a dummy encrypted item.
	mockDynamoDBClient.On("GetItem", mock.Anything, mock.AnythingOfType("*dynamodb.GetItemInput"), mock.Anything).Return(&dynamodb.GetItemOutput{
		Item: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "123"},
			"SK": &types.AttributeValueMemberS{Value: "456"},
			// Encrypted attributes
			"EncryptedData": &types.AttributeValueMemberB{Value: []byte(`{"S":"encrypted-value"}`)},
		},
	}, nil)

	// Mock decryption materials call
	mockCMProvider.On("DecryptionMaterials", mock.Anything, mock.Anything, mock.Anything).Return(materials.NewDecryptionMaterials(
		map[string]string{"mock": "data"},
		&MockDelegatedKey{},
		nil,
	), nil)

	// Test GetItem
	result, err := encryptedClient.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String("test-table"),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "123"},
			"SK": &types.AttributeValueMemberS{Value: "456"},
		},
	})

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.Item)
	mockDynamoDBClient.AssertExpectations(t)
	mockCMProvider.AssertExpectations(t)
}

func TestEncryptedClient_Query(t *testing.T) {
	mockDynamoDBClient := new(MockDynamoDBClient)
	mockCMProvider := new(MockCryptographicMaterialsProvider)
	encryptedClient := NewEncryptedClient(mockDynamoDBClient, mockCMProvider)

	// Mock DescribeTable call to simulate fetching table primary key schema.
	mockDynamoDBClient.On("DescribeTable", mock.Anything, mock.AnythingOfType("*dynamodb.DescribeTableInput"), mock.Anything).Return(&dynamodb.DescribeTableOutput{
		Table: &types.TableDescription{
			KeySchema: []types.KeySchemaElement{
				{AttributeName: aws.String("PK"), KeyType: types.KeyTypeHash},
				{AttributeName: aws.String("SK"), KeyType: types.KeyTypeRange},
			},
		},
	}, nil)

	// Mock Query call to return dummy encrypted items.
	mockDynamoDBClient.On("Query", mock.Anything, mock.AnythingOfType("*dynamodb.QueryInput"), mock.Anything).Return(&dynamodb.QueryOutput{
		Items: []map[string]types.AttributeValue{
			{
				"PK":            &types.AttributeValueMemberS{Value: "123"},
				"SK":            &types.AttributeValueMemberS{Value: "456"},
				"EncryptedData": &types.AttributeValueMemberB{Value: []byte(`{"S":"encrypted-value-1"}`)},
			},
			{
				"PK":            &types.AttributeValueMemberS{Value: "123"},
				"SK":            &types.AttributeValueMemberS{Value: "789"},
				"EncryptedData": &types.AttributeValueMemberB{Value: []byte(`{"S":"encrypted-value-2"}`)},
			},
		},
	}, nil)

	// Mock decryption materials call
	mockCMProvider.On("DecryptionMaterials", mock.Anything, mock.Anything, mock.Anything).Return(materials.NewDecryptionMaterials(
		map[string]string{"mock": "data"},
		&MockDelegatedKey{},
		nil,
	), nil)

	// Test Query
	result, err := encryptedClient.Query(context.Background(), &dynamodb.QueryInput{
		TableName:              aws.String("test-table"),
		KeyConditionExpression: aws.String("PK = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: "123"},
		},
	})

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Items, 2)
	mockDynamoDBClient.AssertExpectations(t)
	mockCMProvider.AssertExpectations(t)
}

func TestEncryptedClient_Scan(t *testing.T) {
	mockDynamoDBClient := new(MockDynamoDBClient)
	mockCMProvider := new(MockCryptographicMaterialsProvider)
	encryptedClient := NewEncryptedClient(mockDynamoDBClient, mockCMProvider)

	// Mock DescribeTable call to simulate fetching table primary key schema.
	mockDynamoDBClient.On("DescribeTable", mock.Anything, mock.AnythingOfType("*dynamodb.DescribeTableInput"), mock.Anything).Return(&dynamodb.DescribeTableOutput{
		Table: &types.TableDescription{
			KeySchema: []types.KeySchemaElement{
				{AttributeName: aws.String("PK"), KeyType: types.KeyTypeHash},
				{AttributeName: aws.String("SK"), KeyType: types.KeyTypeRange},
			},
		},
	}, nil)

	// Mock Scan call to return dummy encrypted items.
	mockDynamoDBClient.On("Scan", mock.Anything, mock.AnythingOfType("*dynamodb.ScanInput"), mock.Anything).Return(&dynamodb.ScanOutput{
		Items: []map[string]types.AttributeValue{
			{
				"PK":            &types.AttributeValueMemberS{Value: "123"},
				"SK":            &types.AttributeValueMemberS{Value: "456"},
				"EncryptedData": &types.AttributeValueMemberB{Value: []byte(`{"S":"encrypted-value-1"}`)},
			},
			{
				"PK":            &types.AttributeValueMemberS{Value: "789"},
				"SK":            &types.AttributeValueMemberS{Value: "012"},
				"EncryptedData": &types.AttributeValueMemberB{Value: []byte(`{"S":"encrypted-value-2"}`)},
			},
		},
	}, nil)

	// Mock decryption materials call
	mockCMProvider.On("DecryptionMaterials", mock.Anything, mock.Anything, mock.Anything).Return(materials.NewDecryptionMaterials(
		map[string]string{"mock": "data"},
		&MockDelegatedKey{},
		nil,
	), nil)

	// Test Scan
	result, err := encryptedClient.Scan(context.Background(), &dynamodb.ScanInput{
		TableName: aws.String("test-table"),
	})

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Items, 2)
	mockDynamoDBClient.AssertExpectations(t)
	mockCMProvider.AssertExpectations(t)
}

func TestEncryptedClient_BatchGetItem(t *testing.T) {
	mockDynamoDBClient := new(MockDynamoDBClient)
	mockCMProvider := new(MockCryptographicMaterialsProvider)
	encryptedClient := NewEncryptedClient(mockDynamoDBClient, mockCMProvider)

	// Mock DescribeTable call to simulate fetching table primary key schema.
	mockDynamoDBClient.On("DescribeTable", mock.Anything, mock.AnythingOfType("*dynamodb.DescribeTableInput"), mock.Anything).Return(&dynamodb.DescribeTableOutput{
		Table: &types.TableDescription{
			KeySchema: []types.KeySchemaElement{
				{AttributeName: aws.String("PK"), KeyType: types.KeyTypeHash},
				{AttributeName: aws.String("SK"), KeyType: types.KeyTypeRange},
			},
		},
	}, nil)

	// Mock BatchGetItem call to return dummy encrypted items.
	mockDynamoDBClient.On("BatchGetItem", mock.Anything, mock.AnythingOfType("*dynamodb.BatchGetItemInput"), mock.Anything).Return(&dynamodb.BatchGetItemOutput{
		Responses: map[string][]map[string]types.AttributeValue{
			"test-table": {
				{
					"PK":            &types.AttributeValueMemberS{Value: "123"},
					"SK":            &types.AttributeValueMemberS{Value: "456"},
					"EncryptedData": &types.AttributeValueMemberB{Value: []byte(`{"S":"encrypted-value-1"}`)},
				},
				{
					"PK":            &types.AttributeValueMemberS{Value: "789"},
					"SK":            &types.AttributeValueMemberS{Value: "012"},
					"EncryptedData": &types.AttributeValueMemberB{Value: []byte(`{"S":"encrypted-value-2"}`)},
				},
			},
		},
	}, nil)

	// Mock decryption materials call
	mockCMProvider.On("DecryptionMaterials", mock.Anything, mock.Anything, mock.Anything).Return(materials.NewDecryptionMaterials(
		map[string]string{"mock": "data"},
		&MockDelegatedKey{},
		nil,
	), nil)

	// Test BatchGetItem
	result, err := encryptedClient.BatchGetItem(context.Background(), &dynamodb.BatchGetItemInput{
		RequestItems: map[string]types.KeysAndAttributes{
			"test-table": {
				Keys: []map[string]types.AttributeValue{
					{
						"PK": &types.AttributeValueMemberS{Value: "123"},
						"SK": &types.AttributeValueMemberS{Value: "456"},
					},
					{
						"PK": &types.AttributeValueMemberS{Value: "789"},
						"SK": &types.AttributeValueMemberS{Value: "012"},
					},
				},
			},
		},
	})

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Responses["test-table"], 2)
	mockDynamoDBClient.AssertExpectations(t)
	mockCMProvider.AssertExpectations(t)
}

func TestEncryptedClient_BatchWriteItem(t *testing.T) {
	mockDynamoDBClient := new(MockDynamoDBClient)
	mockCMProvider := new(MockCryptographicMaterialsProvider)
	encryptedClient := NewEncryptedClient(mockDynamoDBClient, mockCMProvider)

	// Mock DescribeTable call to simulate fetching table primary key schema.
	mockDynamoDBClient.On("DescribeTable", mock.Anything, mock.AnythingOfType("*dynamodb.DescribeTableInput"), mock.Anything).Return(&dynamodb.DescribeTableOutput{
		Table: &types.TableDescription{
			KeySchema: []types.KeySchemaElement{
				{AttributeName: aws.String("PK"), KeyType: types.KeyTypeHash},
				{AttributeName: aws.String("SK"), KeyType: types.KeyTypeRange},
			},
		},
	}, nil)

	// Mock BatchWriteItem call to return a successful response.
	mockDynamoDBClient.On("BatchWriteItem", mock.Anything, mock.AnythingOfType("*dynamodb.BatchWriteItemInput"), mock.Anything).Return(&dynamodb.BatchWriteItemOutput{}, nil)

	// Mock encryption materials call
	mockCMProvider.On("EncryptionMaterials", mock.Anything, mock.Anything).Return(materials.NewEncryptionMaterials(
		map[string]string{"mock": "data"},
		&MockDelegatedKey{},
		nil,
	), nil)

	// Test BatchWriteItem
	result, err := encryptedClient.BatchWriteItem(context.Background(), &dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]types.WriteRequest{
			"test-table": {
				{
					PutRequest: &types.PutRequest{
						Item: map[string]types.AttributeValue{
							"PK":         &types.AttributeValueMemberS{Value: "123"},
							"SK":         &types.AttributeValueMemberS{Value: "456"},
							"Attribute1": &types.AttributeValueMemberS{Value: "Value1"},
						},
					},
				},
				{
					PutRequest: &types.PutRequest{
						Item: map[string]types.AttributeValue{
							"PK":         &types.AttributeValueMemberS{Value: "789"},
							"SK":         &types.AttributeValueMemberS{Value: "012"},
							"Attribute2": &types.AttributeValueMemberS{Value: "Value2"},
						},
					},
				},
			},
		},
	})

	assert.NoError(t, err)
	assert.NotNil(t, result)
	mockDynamoDBClient.AssertExpectations(t)
	mockCMProvider.AssertExpectations(t)
}

func TestEncryptedClient_DeleteItem(t *testing.T) {
	mockDynamoDBClient := new(MockDynamoDBClient)
	mockCMProvider := new(MockCryptographicMaterialsProvider)
	encryptedClient := NewEncryptedClient(mockDynamoDBClient, mockCMProvider)

	// Mock DescribeTable call to simulate fetching table primary key schema.
	mockDynamoDBClient.On("DescribeTable", mock.Anything, mock.AnythingOfType("*dynamodb.DescribeTableInput"), mock.Anything).Return(&dynamodb.DescribeTableOutput{
		Table: &types.TableDescription{
			KeySchema: []types.KeySchemaElement{
				{AttributeName: aws.String("PK"), KeyType: types.KeyTypeHash},
				{AttributeName: aws.String("SK"), KeyType: types.KeyTypeRange},
			},
		},
	}, nil)

	// Mock DeleteItem call to return a successful response.
	mockDynamoDBClient.On("DeleteItem", mock.Anything, mock.AnythingOfType("*dynamodb.DeleteItemInput"), mock.Anything).Return(&dynamodb.DeleteItemOutput{
		Attributes: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "123"},
			"SK": &types.AttributeValueMemberS{Value: "456"},
		},
	}, nil)

	// Mock Query call to return a successful response with matching metadata items.
	mockDynamoDBClient.On("Query", mock.Anything, mock.AnythingOfType("*dynamodb.QueryInput"), mock.Anything).Return(&dynamodb.QueryOutput{
		Items: []map[string]types.AttributeValue{
			{
				"MaterialName": &types.AttributeValueMemberS{Value: "test-material"},
				"Version":      &types.AttributeValueMemberN{Value: "1"},
			},
		},
	}, nil)

	// Mock BatchWriteItem call to return a successful response.
	mockDynamoDBClient.On("BatchWriteItem", mock.Anything, mock.AnythingOfType("*dynamodb.BatchWriteItemInput"), mock.Anything).Return(&dynamodb.BatchWriteItemOutput{}, nil)

	// Mock TableName call
	mockCMProvider.On("TableName").Return("test-table").Maybe()

	// Test DeleteItem
	result, err := encryptedClient.DeleteItem(context.Background(), &dynamodb.DeleteItemInput{
		TableName: aws.String("test-table"),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "123"},
			"SK": &types.AttributeValueMemberS{Value: "456"},
		},
		ReturnValues: types.ReturnValueAllOld,
	})

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "123", result.Attributes["PK"].(*types.AttributeValueMemberS).Value)
	assert.Equal(t, "456", result.Attributes["SK"].(*types.AttributeValueMemberS).Value)
	mockDynamoDBClient.AssertExpectations(t)
	mockCMProvider.AssertExpectations(t)
}
