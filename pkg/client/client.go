package client

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/crypto"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/provider"
)

type CryptoAction int

const (
	CryptoActionEncrypt CryptoAction = iota
	CryptoActionEncryptDeterministically
	CryptoActionSign
	CryptoActionDoNothing
)

type AttributeActions struct {
	DefaultAction      CryptoAction
	AttributeActionMap map[string]CryptoAction
}

func NewAttributeActions() *AttributeActions {
	return &AttributeActions{
		DefaultAction:      CryptoActionEncrypt,
		AttributeActionMap: make(map[string]CryptoAction),
	}
}

func (aa *AttributeActions) WithDefaultAction(action CryptoAction) *AttributeActions {
	aa.DefaultAction = action
	return aa
}

func (aa *AttributeActions) WithAttributeAction(attributeName string, action CryptoAction) *AttributeActions {
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

	// Create the encryption context based on the key attributes
	encryptionContext := make(map[string]string)
	if partitionKeyValue, ok := input.Item[schema.PartitionKey]; ok {
		if partitionKeyValue.S != nil {
			encryptionContext[schema.PartitionKey] = *partitionKeyValue.S
		} else if partitionKeyValue.N != nil {
			encryptionContext[schema.PartitionKey] = *partitionKeyValue.N
		}
	}
	if schema.SortKey != "" {
		if sortKeyValue, ok := input.Item[schema.SortKey]; ok {
			if sortKeyValue.S != nil {
				encryptionContext[schema.SortKey] = *sortKeyValue.S
			} else if sortKeyValue.N != nil {
				encryptionContext[schema.SortKey] = *sortKeyValue.N
			}
		}
	}

	encryptionMaterials, err := c.materialsProvider.EncryptionMaterials(ctx, encryptionContext)
	if err != nil {
		return nil, err
	}

	encryptedItem := make(map[string]*dynamodb.AttributeValue)
	for k, v := range input.Item {
		if k == schema.PartitionKey || k == schema.SortKey {
			encryptedItem[k] = v
			continue
		}

		action := c.attributeActions.DefaultAction
		if specificAction, ok := c.attributeActions.AttributeActionMap[k]; ok {
			action = specificAction
		}

		switch action {
		case CryptoActionEncrypt:
			ciphertext, err := c.cryptoProvider.EncryptAttribute(k, v)
			if err != nil {
				return nil, err
			}
			encryptedItem[k] = ciphertext
			encryptedItem[fmt.Sprintf("__encryption_method-for_for-%s", k)] = &dynamodb.AttributeValue{S: aws.String("aead")}
		case CryptoActionEncryptDeterministically:
			ciphertext, err := c.cryptoProvider.EncryptAttributeDeterministically(k, v)
			if err != nil {
				return nil, err
			}
			encryptedItem[k] = ciphertext
			encryptedItem[fmt.Sprintf("__encryption_method_for-%s", k)] = &dynamodb.AttributeValue{S: aws.String("daead")}
		case CryptoActionSign:
			// TODO: Implement signing logic
			encryptedItem[k] = v
		case CryptoActionDoNothing:
			encryptedItem[k] = v
		}
	}

	for k, v := range encryptionMaterials {
		encryptedItem[k] = v
	}

	input.Item = encryptedItem

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

	// Create the decryption context based on the key attributes
	decryptionContext := make(map[string]string)
	if partitionKeyValue, ok := output.Item[schema.PartitionKey]; ok && partitionKeyValue != nil {
		decryptionContext[schema.PartitionKey] = c.getValueFromAttribute(partitionKeyValue)
	}
	if schema.SortKey != "" && output.Item[schema.SortKey] != nil {
		sortKeyValue := output.Item[schema.SortKey]
		decryptionContext[schema.SortKey] = c.getValueFromAttribute(sortKeyValue)
	}

	decryptedItem := make(map[string]*dynamodb.AttributeValue)
	for k, v := range output.Item {
		if k == provider.WrappedDataKeyAttrName || strings.HasPrefix(k, "__encryption_method") {
			continue
		}
		if v.B != nil {
			var plaintext *dynamodb.AttributeValue
			var err error
			encryptionMethodAttr := output.Item[fmt.Sprintf("__encryption_method_for-%s", k)]
			if encryptionMethodAttr != nil && encryptionMethodAttr.S != nil {
				encryptionMethod := *encryptionMethodAttr.S
				switch encryptionMethod {
				case "daead":
					plaintext, err = c.cryptoProvider.DecryptAttributeDeterministically(k, v.B)
				case "aead":
					plaintext, err = c.cryptoProvider.DecryptAttribute(k, v.B)
				default:
					return nil, fmt.Errorf("unsupported encryption method: %s", encryptionMethod)
				}
			} else {
				// If encryption method is not found, default to regular decryption
				plaintext, err = c.cryptoProvider.DecryptAttribute(k, v.B)
			}
			if err != nil {
				return nil, err
			}
			decryptedItem[k] = plaintext
		} else {
			decryptedItem[k] = v
		}
	}

	output.Item = decryptedItem

	return output, nil
}

func (c *EncryptedClient) getKeySchema(tableName string) (TableKeySchema, error) {
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
		if *keySchemaElement.KeyType == "HASH" {
			schema.PartitionKey = *keySchemaElement.AttributeName
		} else if *keySchemaElement.KeyType == "RANGE" {
			schema.SortKey = *keySchemaElement.AttributeName
		}
	}

	c.tableKeySchemas[tableName] = schema

	return schema, nil
}

func (c *EncryptedClient) getValueFromAttribute(attr *dynamodb.AttributeValue) string {
	if attr == nil {
		return ""
	}

	switch {
	case attr.S != nil:
		return *attr.S
	default:
		return ""
	}
}
