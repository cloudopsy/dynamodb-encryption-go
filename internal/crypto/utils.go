package crypto

import (
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// marshalAttributeValue converts a DynamoDB attribute to a byte slice.
func marshalAttributeValue(attr types.AttributeValue) ([]byte, error) {
	var val interface{}
	if err := attributevalue.Unmarshal(attr, &val); err != nil {
		return nil, fmt.Errorf("unmarshal DynamoDB attribute: %w", err)
	}
	return json.Marshal(val)
}

// unmarshalAttributeValue converts a byte slice to a DynamoDB attribute.
func unmarshalAttributeValue(data []byte) (types.AttributeValue, error) {
	var val interface{}
	if err := json.Unmarshal(data, &val); err != nil {
		return nil, fmt.Errorf("unmarshal JSON: %w", err)
	}
	return attributevalue.Marshal(val)
}
