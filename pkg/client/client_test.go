package client

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stretchr/testify/assert"
)

type mockDynamoDB struct {
	item map[string]types.AttributeValue
	err  error
}

func (m *mockDynamoDB) PutItem(ctx context.Context, input *dynamodb.PutItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	m.item = input.Item
	return &dynamodb.PutItemOutput{}, m.err
}

func (m *mockDynamoDB) GetItem(ctx context.Context, input *dynamodb.GetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	return &dynamodb.GetItemOutput{Item: m.item}, m.err
}

type mockMaterialsProvider struct {
	encryptionMaterials map[string]types.AttributeValue
	decryptionMaterials map[string]types.AttributeValue
	err                 error
}

func (m *mockMaterialsProvider) EncryptionMaterials(ctx context.Context, item map[string]types.AttributeValue) (map[string]types.AttributeValue, error) {
	return m.encryptionMaterials, m.err
}

func (m *mockMaterialsProvider) DecryptionMaterials(ctx context.Context, item map[string]types.AttributeValue) (map[string]types.AttributeValue, error) {
	return m.decryptionMaterials, m.err
}

func (m *mockMaterialsProvider) EncryptAttribute(ctx context.Context, attributeName string, attributeValue types.AttributeValue) (types.AttributeValue, error) {
	return attributeValue, nil
}

func (m *mockMaterialsProvider) DecryptAttribute(ctx context.Context, attributeName string, attributeValue types.AttributeValue) (types.AttributeValue, error) {
	return attributeValue, nil
}

func TestEncryptedClient_PutItem(t *testing.T) {
	mockDB := &mockDynamoDB{}
	mockProvider := &mockMaterialsProvider{
		encryptionMaterials: map[string]types.AttributeValue{"key": &types.AttributeValueMemberS{Value: "value"}},
	}
	client := NewEncryptedClient(mockDB, mockProvider)
	input := &dynamodb.PutItemInput{
		Item: map[string]types.AttributeValue{"id": &types.AttributeValueMemberS{Value: "123"}},
	}
	_, err := client.PutItem(context.Background(), input)
	assert.NoError(t, err)
	assert.Contains(t, mockDB.item, "key")
}

func TestEncryptedClient_GetItem(t *testing.T) {
	item := map[string]types.AttributeValue{"id": &types.AttributeValueMemberS{Value: "123"}}
	mockDB := &mockDynamoDB{item: item}
	mockProvider := &mockMaterialsProvider{
		decryptionMaterials: map[string]types.AttributeValue{"key": &types.AttributeValueMemberS{Value: "value"}},
	}
	client := NewEncryptedClient(mockDB, mockProvider)
	input := &dynamodb.GetItemInput{
		Key: map[string]types.AttributeValue{"id": &types.AttributeValueMemberS{Value: "124"}},
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
		Item: map[string]types.AttributeValue{"id": &types.AttributeValueMemberS{Value: "123"}},
	}
	_, err := client.PutItem(context.Background(), input)
	assert.Error(t, err)
}

func TestEncryptedClient_GetItem_Error(t *testing.T) {
	mockDB := &mockDynamoDB{err: errors.New("get item error")}
	mockProvider := &mockMaterialsProvider{}
	client := NewEncryptedClient(mockDB, mockProvider)
	input := &dynamodb.GetItemInput{
		Key: map[string]types.AttributeValue{"id": &types.AttributeValueMemberS{Value: "123"}},
	}
	_, err := client.GetItem(context.Background(), input)
	assert.Error(t, err)
}
