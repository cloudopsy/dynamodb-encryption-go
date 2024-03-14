package client

import (
	"context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/crypto"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/provider"
)

type AttributeActions struct {
	DefaultAction      crypto.Action
	AttributeActionMap map[string]crypto.Action
}

func NewAttributeActions() *AttributeActions {
	return &AttributeActions{
		DefaultAction:      crypto.Encrypt,
		AttributeActionMap: make(map[string]crypto.Action),
	}
}

// WithDefaultAction sets the default action for all attributes
func (aa *AttributeActions) WithDefaultAction(action crypto.Action) *AttributeActions {
	aa.DefaultAction = action
	return aa
}

// WithAttributeAction sets the action for a specific attribute
func (aa *AttributeActions) WithAttributeAction(attributeName string, action crypto.Action) *AttributeActions {
	aa.AttributeActionMap[attributeName] = action
	return aa
}

type TableKeySchema struct {
	PartitionKey string
	SortKey      string
}

type EncryptedClient struct {
	client            dynamodb.DynamoDB
	cryptoProvider    crypto.Crypto
	materialsProvider provider.CryptographicMaterialsProvider
	attributeActions  *AttributeActions
	tableKeySchemas   map[string]TableKeySchema
}

// NewEncryptedClient creates a new EncryptedClient
func NewEncryptedClient(client *dynamodb.DynamoDB, cryptoProvider *crypto.Crypto, materialsProvider *provider.CryptographicMaterialsProvider, attributeActions *AttributeActions) *EncryptedClient {
	return &EncryptedClient{
		client:            *client,
		cryptoProvider:    *cryptoProvider,
		materialsProvider: *materialsProvider,
		attributeActions:  attributeActions,
		tableKeySchemas:   make(map[string]TableKeySchema),
	}
}

func (c *EncryptedClient) PutItem(ctx context.Context, input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	tableName := *input.TableName
	schema, err := c.getKeySchema(tableName)
	if err != nil {
		return nil, err
	}

	encryptionContext := c.getContext(schema, input.Item)
	encryptionMaterials, err := c.materialsProvider.EncryptionMaterials(encryptionContext)
	if err != nil {
		return nil, err
	}

	for k, v := range input.Item {
		if _, isKey := encryptionContext[k]; isKey {
			// If the attribute is a key, skip encryption.
			continue
		}

		action := c.attributeActions.DefaultAction
		if specificAction, ok := c.attributeActions.AttributeActionMap[k]; ok {
			action = specificAction
		}
		ciphertext, err := c.cryptoProvider.EncryptAttribute(k, v, action)
		if err != nil {
			return nil, err
		}
		input.Item[k] = ciphertext
	}

	for k, v := range encryptionMaterials {
		input.Item[k] = v
	}

	return c.client.PutItemWithContext(ctx, input)
}

func (c *EncryptedClient) GetItem(ctx context.Context, input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	output, err := c.client.GetItemWithContext(ctx, input)
	if err != nil {
		return nil, err
	}

	tableName := *input.TableName
	schema, err := c.getKeySchema(tableName)
	if err != nil {
		return nil, err
	}

	decryptionContext := c.getContext(schema, output.Item)

	for k, v := range output.Item {
		// Skip the decryption process for key attributes and wrapped data key
		if _, isKey := decryptionContext[k]; isKey || k == provider.WrappedDataKeyAttrName {
			continue
		}

		decryptedAttribute, err := c.cryptoProvider.DecryptAttribute(k, v)
		if err != nil {
			return nil, err
		}
		output.Item[k] = decryptedAttribute
	}

	// Remove the wrapped data key from the output
	delete(output.Item, provider.WrappedDataKeyAttrName)

	return output, nil
}

func (c *EncryptedClient) getKeySchema(tableName string) (TableKeySchema, error) {
	// Check cache first
	if schema, ok := c.tableKeySchemas[tableName]; ok {
		return schema, nil
	}

	descOut, err := c.client.DescribeTable(&dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	if err != nil {
		return TableKeySchema{}, err
	}

	var schema TableKeySchema
	for _, keySchemaElement := range descOut.Table.KeySchema {
		switch *keySchemaElement.KeyType {
		case "HASH":
			schema.PartitionKey = *keySchemaElement.AttributeName
		case "RANGE":
			schema.SortKey = *keySchemaElement.AttributeName
		}
	}

	// Cache the schema for future calls
	c.tableKeySchemas[tableName] = schema

	return schema, nil
}

func (c *EncryptedClient) getValueFromAttribute(attr *dynamodb.AttributeValue) string {
	if attr.S != nil {
		return *attr.S
	}
	if attr.N != nil {
		return *attr.N
	}
	return ""
}

func (c *EncryptedClient) getContext(schema TableKeySchema, item map[string]*dynamodb.AttributeValue) map[string]string {
	context := make(map[string]string)
	for _, key := range []string{schema.PartitionKey, schema.SortKey} {
		if key != "" {
			if value, exists := item[key]; exists && value != nil {
				context[key] = c.getValueFromAttribute(value)
			}
		}
	}
	return context
}
