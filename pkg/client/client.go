package client

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"

	"github.com/cloudopsy/dynamodb-encryption-go/pkg/provider"
)

type CryptoAction int

const (
	CryptoActionEncrypt CryptoAction = iota
	CryptoActionEncryptDeterministicly
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
	materialsProvider provider.CryptographicMaterialsProvider
	attributeActions  *AttributeActions
	tableKeySchemas   map[string]TableKeySchema
}

func NewEncryptedClient(client *dynamodb.DynamoDB, materialsProvider provider.CryptographicMaterialsProvider, attributeActions *AttributeActions) *EncryptedClient {
	return &EncryptedClient{
		client:            *client,
		materialsProvider: materialsProvider,
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
			var plaintext []byte
			if v.S != nil {
				plaintext = []byte(*v.S)
			} else if v.N != nil {
				plaintext = []byte(*v.N)
			} else if v.B != nil {
				plaintext = v.B
			} else {
				encryptedItem[k] = v
				continue
			}

			ciphertext, err := encryptionMaterials.EncryptionKey.Encrypt(plaintext, []byte(k))
			if err != nil {
				return nil, err
			}
			encryptedItem[k] = &dynamodb.AttributeValue{B: ciphertext}
			encryptedItem[fmt.Sprintf("%s-encryption-method", k)] = &dynamodb.AttributeValue{S: aws.String("aead")}

		case CryptoActionEncryptDeterministicly:
			var plaintext []byte
			if v.S != nil {
				plaintext = []byte(*v.S)
			} else if v.N != nil {
				plaintext = []byte(*v.N)
			} else if v.B != nil {
				plaintext = v.B
			} else {
				encryptedItem[k] = v
				continue
			}

			fmt.Println("Encryption Associated data: ", k)

			ciphertext, err := encryptionMaterials.DeterministicAEADKey.EncryptDeterministically(plaintext, []byte(k))
			if err != nil {
				return nil, err
			}
			encryptedItem[k] = &dynamodb.AttributeValue{B: ciphertext}
			encryptedItem[fmt.Sprintf("%s-encryption-method", k)] = &dynamodb.AttributeValue{S: aws.String("deterministic")}
		case CryptoActionSign:
			// TODO: Implement signing logic
			encryptedItem[k] = v
		case CryptoActionDoNothing:
			encryptedItem[k] = v
		}
	}

	encryptedItem[provider.WrappedDataKeyAttrName] = &dynamodb.AttributeValue{S: aws.String(encryptionMaterials.Description[provider.WrappedDataKeyAttrName])}
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

	// Create the decryption context based on the key attributes and the wrapped data key
	decryptionContext := make(map[string]string)
	if partitionKeyValue, ok := output.Item[schema.PartitionKey]; ok {
		if partitionKeyValue.S != nil {
			decryptionContext[schema.PartitionKey] = *partitionKeyValue.S
		} else if partitionKeyValue.N != nil {
			decryptionContext[schema.PartitionKey] = *partitionKeyValue.N
		}
	}
	if schema.SortKey != "" {
		if sortKeyValue, ok := output.Item[schema.SortKey]; ok {
			if sortKeyValue.S != nil {
				decryptionContext[schema.SortKey] = *sortKeyValue.S
			} else if sortKeyValue.N != nil {
				decryptionContext[schema.SortKey] = *sortKeyValue.N
			}
		}
	}
	if wrappedDataKey, ok := output.Item[provider.WrappedDataKeyAttrName]; ok && wrappedDataKey.S != nil {
		decryptionContext[provider.WrappedDataKeyAttrName] = *wrappedDataKey.S
	}

	decryptionMaterials, err := c.materialsProvider.DecryptionMaterials(ctx, decryptionContext)
	if err != nil {
		return nil, err
	}

	decryptedItem := make(map[string]*dynamodb.AttributeValue)
	for k, v := range output.Item {
		if k == provider.WrappedDataKeyAttrName {
			continue
		}
		if strings.HasSuffix(k, "-encryption-method") {
			continue
		}
		if v.B != nil {
			var plaintext []byte
			var err error
			encryptionMethodAttr := output.Item[fmt.Sprintf("%s-encryption-method", k)]
			if encryptionMethodAttr != nil && encryptionMethodAttr.S != nil {
				encryptionMethod := *encryptionMethodAttr.S
				switch encryptionMethod {
				case "deterministic":
					fmt.Println("Decryption Associated data: ", k)
					plaintext, err = decryptionMaterials.DeterministicAEADKey.DecryptDeterministically(v.B, []byte(k))
				case "aead":
					plaintext, err = decryptionMaterials.DecryptionKey.Decrypt(v.B, []byte(k))
				default:
					return nil, fmt.Errorf("unsupported encryption method: %s", encryptionMethod)
				}
			} else {
				// If encryption method is not found, default to regular decryption
				plaintext, err = decryptionMaterials.DecryptionKey.Decrypt(v.B, []byte(k))
			}

			if err != nil {
				return nil, err
			}
			decryptedItem[k] = &dynamodb.AttributeValue{S: aws.String(string(plaintext))}
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
