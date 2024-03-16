package client

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/stretchr/testify/assert"
)

type mockDynamoDB struct {
	dynamodbiface.DynamoDBAPI
	item map[string]*dynamodb.AttributeValue
	err  error
}

func (m *mockDynamoDB) PutItemWithContext(ctx aws.Context, input *dynamodb.PutItemInput, opts ...request.Option) (*dynamodb.PutItemOutput, error) {
	m.item = input.Item
	return &dynamodb.PutItemOutput{}, m.err
}

func (m *mockDynamoDB) GetItemWithContext(ctx aws.Context, input *dynamodb.GetItemInput, opts ...request.Option) (*dynamodb.GetItemOutput, error) {
	return &dynamodb.GetItemOutput{Item: m.item}, m.err
}

type mockMaterialsProvider struct {
	encryptionMaterials map[string]*dynamodb.AttributeValue
	decryptionMaterials map[string]*dynamodb.AttributeValue
	err                 error
}

func (m *mockMaterialsProvider) EncryptionMaterials(ctx context.Context, item map[string]*dynamodb.AttributeValue) (map[string]*dynamodb.AttributeValue, error) {
	return m.encryptionMaterials, m.err
}

func (m *mockMaterialsProvider) DecryptionMaterials(ctx context.Context, item map[string]*dynamodb.AttributeValue) (map[string]*dynamodb.AttributeValue, error) {
	return m.decryptionMaterials, m.err
}

func (m *mockMaterialsProvider) EncryptAttribute(ctx context.Context, attributeName string, attributeValue *dynamodb.AttributeValue) (*dynamodb.AttributeValue, error) {
	return attributeValue, nil
}

func (m *mockMaterialsProvider) DecryptAttribute(ctx context.Context, attributeName string, attributeValue *dynamodb.AttributeValue) (*dynamodb.AttributeValue, error) {
	return attributeValue, nil
}

func TestEncryptedClient_PutItem(t *testing.T) {
	mockDB := &mockDynamoDB{}
	mockProvider := &mockMaterialsProvider{
		encryptionMaterials: map[string]*dynamodb.AttributeValue{"key": {S: aws.String("value")}},
	}
	client := NewEncryptedClient(mockDB, mockProvider)

	input := &dynamodb.PutItemInput{
		Item: map[string]*dynamodb.AttributeValue{"id": {S: aws.String("123")}},
	}

	_, err := client.PutItem(context.Background(), input)
	assert.NoError(t, err)
	assert.Contains(t, mockDB.item, "key")
}

func TestEncryptedClient_GetItem(t *testing.T) {
	item := map[string]*dynamodb.AttributeValue{"id": {S: aws.String("123")}}
	mockDB := &mockDynamoDB{item: item}
	mockProvider := &mockMaterialsProvider{
		decryptionMaterials: map[string]*dynamodb.AttributeValue{"key": {S: aws.String("value")}},
	}
	client := NewEncryptedClient(mockDB, mockProvider)

	input := &dynamodb.GetItemInput{
		Key: map[string]*dynamodb.AttributeValue{"id": {S: aws.String("124")}},
	}

	output, err := client.GetItem(context.Background(), input)
	assert.NoError(t, err)
	assert.Equal(t, item, output.Item)
}

func TestEncryptedClient_PutItem_Error(t *testing.T) {
	mockDB := &mockDynamoDB{err: errors.New("put item error")}
	mockProvider := &mockMaterialsProvider{}
	client := NewEncryptedClient(mockDB, mockProvider)

	input := &dynamodb.PutItemInput{
		Item: map[string]*dynamodb.AttributeValue{"id": {S: aws.String("123")}},
	}

	_, err := client.PutItem(context.Background(), input)
	assert.Error(t, err)
}

func TestEncryptedClient_GetItem_Error(t *testing.T) {
	mockDB := &mockDynamoDB{err: errors.New("get item error")}
	mockProvider := &mockMaterialsProvider{}
	client := NewEncryptedClient(mockDB, mockProvider)

	input := &dynamodb.GetItemInput{
		Key: map[string]*dynamodb.AttributeValue{"id": {S: aws.String("123")}},
	}

	_, err := client.GetItem(context.Background(), input)
	assert.Error(t, err)
}
