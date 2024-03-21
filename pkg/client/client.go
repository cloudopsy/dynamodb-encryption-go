package client

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/provider"
	"github.com/cloudopsy/dynamodb-encryption-go/pkg/utils"
)

// TableKeySchema stores the schema for DynamoDB table keys.
type TableKeySchema struct {
	PartitionKey string
	SortKey      string
}

// EncryptedClient facilitates encrypted operations on DynamoDB items.
type EncryptedClient struct {
	client            DynamoDBAPI
	materialsProvider provider.CryptographicMaterialsProvider
	tableKeySchemas   map[string]TableKeySchema
}

type DynamoDBAPI interface {
	PutItem(ctx context.Context, input *dynamodb.PutItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	GetItem(ctx context.Context, input *dynamodb.GetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
}

// NewEncryptedClient creates a new instance of EncryptedClient.
func NewEncryptedClient(client DynamoDBAPI, materialsProvider provider.CryptographicMaterialsProvider) *EncryptedClient {
	return &EncryptedClient{
		client:            client,
		materialsProvider: materialsProvider,
		tableKeySchemas:   make(map[string]TableKeySchema),
	}
}

// PutItem encrypts an item and puts it into a DynamoDB table.
func (ec *EncryptedClient) PutItem(ctx context.Context, input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	// Create a copy of the original item map to avoid modifying it during encryption
	originalItem := make(map[string]types.AttributeValue)
	for k, v := range input.Item {
		originalItem[k] = v
	}

	encryptionMaterials, err := ec.materialsProvider.EncryptionMaterials(ctx, originalItem)
	if err != nil {
		return nil, fmt.Errorf("generating encryption materials: %v", err)
	}

<<<<<<< HEAD
		switch action {
		case CryptoActionEncrypt:
			attributeBytes, err := utils.AttributeValueToBytes(v)
			if err != nil {
				return nil, err
			}

			ciphertext, err := c.cryptoProvider.Encrypt(attributeBytes, []byte(k)) // Assuming `k` is used as associated data.
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt attribute: %v", err)
			}

			encryptedAttributeValue, err := utils.BytesToAttributeValue(ciphertext)
			if err != nil {
				return nil, err
			}
			encryptedItem[k] = encryptedAttributeValue

		case CryptoActionEncryptDeterministically:
			attributeBytes, err := utils.AttributeValueToBytes(v)
			if err != nil {
				return nil, err
			}

			ciphertext, err := c.cryptoProvider.EncryptDeterministically(attributeBytes, []byte(k))
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt attribute: %v", err)
			}

			encryptedAttributeValue, err := utils.BytesToAttributeValue(ciphertext)
			if err != nil {
				return nil, err
			}
			encryptedItem[k] = encryptedAttributeValue
		case CryptoActionSign:
			// TODO: Implement signing logic
			encryptedItem[k] = v
		case CryptoActionDoNothing:
			encryptedItem[k] = v
		}
=======
	// Encrypt attributes using a copy of the item to preserve the original encryption context.
	encryptedItem, err := ec.encryptAttributes(ctx, originalItem)
	if err != nil {
		return nil, fmt.Errorf("encrypting attributes: %v", err)
>>>>>>> 8f215692218746a35cf2f8ab7c1b1f091dd09197
	}

	for k, v := range encryptionMaterials {
		attr, err := utils.BytesToAttributeValue(v)
		if err != nil {
			return nil, err
		}
		encryptedItem[k] = attr
	}

	input.Item = encryptedItem

	return ec.client.PutItem(ctx, input)
}

// GetItem retrieves an item from a DynamoDB table and decrypts it.
func (ec *EncryptedClient) GetItem(ctx context.Context, input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	output, err := ec.client.GetItem(ctx, input)
	if err != nil {
		return nil, err
	}

	// Generate decryption materials using the extracted encryption context.
	_, err = ec.materialsProvider.DecryptionMaterials(ctx, output.Item)
	if err != nil {
		return nil, fmt.Errorf("generating decryption materials: %v", err)
	}

<<<<<<< HEAD
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
					attributeBytes, err := utils.AttributeValueToBytes(v) // Convert from *dynamodb.AttributeValue to []byte for decryption
					if err != nil {
						return nil, err
					}

					// Assuming Decrypt returns a []byte plaintext
					plaintext, err := c.cryptoProvider.DecryptDeterministically(attributeBytes, []byte(k))
					if err != nil {
						return nil, fmt.Errorf("failed to decrypt attribute: %v", err)
					}

					// Convert plaintext back into *dynamodb.AttributeValue
					decryptedAttributeValue, err := utils.BytesToAttributeValue(plaintext)
					if err != nil {
						return nil, err
					}
					decryptedItem[k] = decryptedAttributeValue

					// plaintext, err = c.cryptoProvider.DecryptAttributeDeterministically(k, v.B)
				case "aead":
					attributeBytes, err := utils.AttributeValueToBytes(v) // Convert from *dynamodb.AttributeValue to []byte for decryption
					if err != nil {
						return nil, err
					}

					// Assuming Decrypt returns a []byte plaintext
					plaintext, err := c.cryptoProvider.Decrypt(attributeBytes, []byte(k))
					if err != nil {
						return nil, fmt.Errorf("failed to decrypt attribute: %v", err)
					}

					// Convert plaintext back into *dynamodb.AttributeValue
					decryptedAttributeValue, err := utils.BytesToAttributeValue(plaintext)
					if err != nil {
						return nil, err
					}
					decryptedItem[k] = decryptedAttributeValue

					// plaintext, err = c.cryptoProvider.DecryptAttribute(k, v.B)
				default:
					return nil, fmt.Errorf("unsupported encryption method: %s", encryptionMethod)
				}
			} else {
				// If encryption method is not found, default to regular decryption
				// plaintext, err = c.cryptoProvider.DecryptAttribute(k, v.B)
				continue
			}
			if err != nil {
				return nil, err
			}
			decryptedItem[k] = plaintext
		} else {
			decryptedItem[k] = v
		}
=======
	// Decrypt attributes using the decryption materials.
	decryptedItem, err := ec.decryptAttributes(ctx, output.Item)
	if err != nil {
		return nil, fmt.Errorf("decrypting attributes: %v", err)
>>>>>>> 8f215692218746a35cf2f8ab7c1b1f091dd09197
	}

	output.Item = decryptedItem

	return output, nil
}

func (ec *EncryptedClient) encryptAttributes(ctx context.Context, item map[string]types.AttributeValue) (map[string]types.AttributeValue, error) {
	encryptedItem := make(map[string]types.AttributeValue)

	for attributeName, attributeValue := range item {
		encryptedAttributeValue, err := ec.materialsProvider.EncryptAttribute(ctx, attributeName, attributeValue)
		if err != nil {
			return nil, fmt.Errorf("encrypting attribute '%s': %v", attributeName, err)
		}
		encryptedItem[attributeName] = encryptedAttributeValue
	}

	return encryptedItem, nil
}

func (ec *EncryptedClient) decryptAttributes(ctx context.Context, item map[string]types.AttributeValue) (map[string]types.AttributeValue, error) {
	decryptedItem := make(map[string]types.AttributeValue)

	for attributeName, attributeValue := range item {
		decryptedAttributeValue, err := ec.materialsProvider.DecryptAttribute(ctx, attributeName, attributeValue)
		if err != nil {
			return nil, fmt.Errorf("decrypting attribute '%s': %v", attributeName, err)
		}
		decryptedItem[attributeName] = decryptedAttributeValue
	}

	return decryptedItem, nil
}
