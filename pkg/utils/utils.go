package utils

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// PrimaryKeyInfo holds information about the primary key of a DynamoDB table.
type PrimaryKeyInfo struct {
	Table        string
	PartitionKey string
	SortKey      string
}

// TableInfo fetches the primary key names of a DynamoDB table.
func TableInfo(ctx context.Context, client *dynamodb.Client, tableName string) (*PrimaryKeyInfo, error) {
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

// HashString takes an input string and returns its SHA256 hash as a hex-encoded string.
func HashString(input string) string {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}

// AttributeValueToString converts a DynamoDB AttributeValue to a string representation.
func AttributeValueToString(value types.AttributeValue) (string, error) {
	switch v := value.(type) {
	case *types.AttributeValueMemberS:
		return v.Value, nil
	case *types.AttributeValueMemberN:
		return v.Value, nil
	case *types.AttributeValueMemberB:
		return base64.StdEncoding.EncodeToString(v.Value), nil
	case *types.AttributeValueMemberBOOL:
		return strconv.FormatBool(v.Value), nil
	case *types.AttributeValueMemberNULL:
		return "", nil
	case *types.AttributeValueMemberM:
		m := make(map[string]string)
		for key, value := range v.Value {
			convertedValue, err := AttributeValueToString(value)
			if err != nil {
				return "", err
			}
			m[key] = convertedValue
		}
		jsonStr, err := json.Marshal(m)
		if err != nil {
			return "", fmt.Errorf("failed to marshal map to JSON: %v", err)
		}
		return string(jsonStr), nil
	case *types.AttributeValueMemberL:
		var l []string
		for _, listItem := range v.Value {
			convertedItem, err := AttributeValueToString(listItem)
			if err != nil {
				return "", err
			}
			l = append(l, convertedItem)
		}
		jsonStr, err := json.Marshal(l)
		if err != nil {
			return "", fmt.Errorf("failed to marshal list to JSON: %v", err)
		}
		return string(jsonStr), nil
	default:
		return "", fmt.Errorf("unsupported AttributeValue type: %T", value)
	}
}

// AttributeValueMapToBytes converts a map of DynamoDB attribute values to a JSON byte slice.
func AttributeValueMapToBytes(attributes map[string]types.AttributeValue) ([]byte, error) {
	// DynamoDB attribute values to a generic map interface{}
	genericMap := make(map[string]interface{})

	for key, attributeValue := range attributes {
		// Convert the DynamoDB types.AttributeValue to a more generic interface{}
		genericValue, err := attributeValueToInterface(attributeValue)
		if err != nil {
			return nil, fmt.Errorf("error converting attribute value to interface{}: %v", err)
		}
		genericMap[key] = genericValue
	}

	// Marshal the generic map to JSON
	bytes, err := json.Marshal(genericMap)
	if err != nil {
		return nil, fmt.Errorf("error marshaling attributes to JSON: %v", err)
	}

	return bytes, nil
}

// AttributeValueToBytes converts a DynamoDB AttributeValue to bytes.
func AttributeValueToBytes(value types.AttributeValue) ([]byte, error) {
	jsonData, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AttributeValue to JSON: %v", err)
	}

	return jsonData, nil
}

// BytesToAttributeValue attempts to convert bytes back into a DynamoDB types.AttributeValue.
func BytesToAttributeValue(data []byte) (types.AttributeValue, error) {
	var av map[string]interface{}
	if err := json.Unmarshal(data, &av); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON to AttributeValue: %v", err)
	}
	return interfaceToAttributeValue(av)
}

// ConstructMaterialName constructs a material name based on an item's primary key.
func ConstructMaterialName(item map[string]types.AttributeValue, pkInfo *PrimaryKeyInfo) (string, error) {
	partitionKeyValue, err := AttributeValueToString(item[pkInfo.PartitionKey])
	if err != nil {
		return "", fmt.Errorf("invalid partition key attribute type: %v", err)
	}

	sortKeyValue := ""
	if pkInfo.SortKey != "" {
		sortKeyValue, err = AttributeValueToString(item[pkInfo.SortKey])
		if err != nil {
			return "", fmt.Errorf("invalid sort key attribute type: %v", err)
		}
	}

	rawMaterialName := pkInfo.Table + "-" + partitionKeyValue
	if sortKeyValue != "" {
		rawMaterialName += "-" + sortKeyValue
	}

	return HashString(rawMaterialName), nil
}

// attributeValueToInterface converts DynamoDB's types.AttributeValue to a generic interface{}.
func attributeValueToInterface(av types.AttributeValue) (interface{}, error) {
	switch v := av.(type) {
	case *types.AttributeValueMemberS:
		return v.Value, nil
	case *types.AttributeValueMemberN:
		return v.Value, nil
	case *types.AttributeValueMemberB:
		return v.Value, nil
	case *types.AttributeValueMemberBOOL:
		return v.Value, nil
	case *types.AttributeValueMemberNULL:
		return nil, nil
	case *types.AttributeValueMemberM:
		m := make(map[string]interface{})
		for key, value := range v.Value {
			convertedValue, err := attributeValueToInterface(value)
			if err != nil {
				return nil, err
			}
			m[key] = convertedValue
		}
		return m, nil
	case *types.AttributeValueMemberL:
		l := make([]interface{}, len(v.Value))
		for i, listItem := range v.Value {
			convertedItem, err := attributeValueToInterface(listItem)
			if err != nil {
				return nil, err
			}
			l[i] = convertedItem
		}
		return l, nil
	default:
		return nil, fmt.Errorf("unsupported AttributeValue type: %T", av)
	}
}

// interfaceToAttributeValue converts a generic interface{} back into DynamoDB's types.AttributeValue.
func interfaceToAttributeValue(v interface{}) (types.AttributeValue, error) {
	switch value := v.(type) {
	case string:
		return &types.AttributeValueMemberS{Value: value}, nil
	case []byte:
		return &types.AttributeValueMemberB{Value: value}, nil
	case bool:
		return &types.AttributeValueMemberBOOL{Value: value}, nil
	case nil:
		return &types.AttributeValueMemberNULL{Value: true}, nil
	case map[string]interface{}:
		m := make(map[string]types.AttributeValue)
		for key, val := range value {
			convertedValue, err := interfaceToAttributeValue(val)
			if err != nil {
				return nil, err
			}
			m[key] = convertedValue
		}
		return &types.AttributeValueMemberM{Value: m}, nil
	case []interface{}:
		l := make([]types.AttributeValue, len(value))
		for i, listItem := range value {
			convertedItem, err := interfaceToAttributeValue(listItem)
			if err != nil {
				return nil, err
			}
			l[i] = convertedItem
		}
		return &types.AttributeValueMemberL{Value: l}, nil
	default:
		return nil, fmt.Errorf("unsupported type: %T", v)
	}
}
