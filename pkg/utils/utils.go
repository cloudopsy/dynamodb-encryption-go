package utils

import (
	"encoding/json"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

// AttributeValueToBytes converts a DynamoDB AttributeValue to a byte slice.
func AttributeValueToBytes(attr *dynamodb.AttributeValue) ([]byte, error) {
	// Marshal the DynamoDB AttributeValue to a map
	attributeMap, err := dynamodbattribute.MarshalMap(attr)
	if err != nil {
		return nil, err
	}

	// Then, marshal the map to a JSON byte slice
	return json.Marshal(attributeMap)
}

// BytesToAttributeValue converts a byte slice to a map of DynamoDB AttributeValue.
func BytesToAttributeValue(data []byte) (*dynamodb.AttributeValue, error) {
	var attributeMap map[string]interface{}
	err := json.Unmarshal(data, &attributeMap)
	if err != nil {
		return nil, err
	}

	// Convert the map to DynamoDB AttributeValues
	return dynamodbattribute.Marshal(attributeMap)
}
