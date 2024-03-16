package crypto

import (
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

// marshalAttributeValue converts a DynamoDB attribute to a byte slice.
func marshalAttributeValue(attr *dynamodb.AttributeValue) ([]byte, error) {
	var val interface{}
	if err := dynamodbattribute.Unmarshal(attr, &val); err != nil {
		return nil, fmt.Errorf("unmarshal DynamoDB attribute: %w", err)
	}
	return json.Marshal(val)
}

// unmarshalAttributeValue converts a byte slice to a DynamoDB attribute.
func unmarshalAttributeValue(data []byte) (*dynamodb.AttributeValue, error) {
	var val interface{}
	if err := json.Unmarshal(data, &val); err != nil {
		return nil, fmt.Errorf("unmarshal JSON: %w", err)
	}
	return dynamodbattribute.Marshal(val)
}
