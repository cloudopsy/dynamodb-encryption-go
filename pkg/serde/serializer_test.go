package serde

import (
	"bytes"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func TestSerializer_SerializeAttribute(t *testing.T) {
	testCases := []struct {
		name      string
		attribute types.AttributeValue
		expected  []byte
	}{
		{
			name:      "Binary",
			attribute: &types.AttributeValueMemberB{Value: []byte{1, 2, 3}},
			expected:  []byte{0, byte(tagBinary), 0, 0, 0, 3, 1, 2, 3},
		},
		{
			name:      "Number",
			attribute: &types.AttributeValueMemberN{Value: "1.234"},
			expected:  []byte{0, byte(tagNumber), 0, 0, 0, 5, 49, 46, 50, 51, 52},
		},
		{
			name:      "String",
			attribute: &types.AttributeValueMemberS{Value: "hello"},
			expected:  []byte{0, byte(tagString), 0, 0, 0, 5, 104, 101, 108, 108, 111},
		},
		{
			name:      "Boolean (true)",
			attribute: &types.AttributeValueMemberBOOL{Value: true},
			expected:  []byte{0, byte(tagBoolean), 1},
		},
		{
			name:      "Boolean (false)",
			attribute: &types.AttributeValueMemberBOOL{Value: false},
			expected:  []byte{0, byte(tagBoolean), 0},
		},
		{
			name:      "Null",
			attribute: &types.AttributeValueMemberNULL{Value: true},
			expected:  []byte{0, byte(tagNull)},
		},
		{
			name: "List",
			attribute: &types.AttributeValueMemberL{Value: []types.AttributeValue{
				&types.AttributeValueMemberS{Value: "a"},
				&types.AttributeValueMemberS{Value: "b"},
			}},
			expected: []byte{
				0, byte(tagList), 0, 0, 0, 2,
				0, byte(tagString), 0, 0, 0, 1, 97,
				0, byte(tagString), 0, 0, 0, 1, 98,
			},
		},
		{
			name: "Map",
			attribute: &types.AttributeValueMemberM{Value: map[string]types.AttributeValue{
				"key":  &types.AttributeValueMemberS{Value: "value"},
				"key2": &types.AttributeValueMemberN{Value: "2"},
			}},
			expected: []byte{
				0, byte(tagMap), 0, 0, 0, 2,
				0, byte(tagString), 0, 0, 0, 3, 107, 101, 121,
				0, byte(tagString), 0, 0, 0, 5, 118, 97, 108, 117, 101,
				0, byte(tagString), 0, 0, 0, 4, 107, 101, 121, 50,
				0, byte(tagNumber), 0, 0, 0, 1, 50,
			},
		},
		{
			name:      "Binary Set",
			attribute: &types.AttributeValueMemberBS{Value: [][]byte{{1, 2}, {3, 4}}},
			expected: []byte{
				0, byte(tagBinarySet), 0, 0, 0, 2,
				0, 0, 0, 2, 1, 2,
				0, 0, 0, 2, 3, 4,
			},
		},
		{
			name:      "Number Set",
			attribute: &types.AttributeValueMemberNS{Value: []string{"1.234", "5.678"}},
			expected: []byte{
				0, byte(tagNumberSet), 0, 0, 0, 2,
				0, 0, 0, 5, 49, 46, 50, 51, 52,
				0, 0, 0, 5, 53, 46, 54, 55, 56,
			},
		},
		{
			name:      "String Set",
			attribute: &types.AttributeValueMemberSS{Value: []string{"hello", "world"}},
			expected: []byte{
				0, byte(tagStringSet), 0, 0, 0, 2,
				0, 0, 0, 5, 104, 101, 108, 108, 111,
				0, 0, 0, 5, 119, 111, 114, 108, 100,
			},
		},
	}

	serializer := NewSerializer()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := serializer.SerializeAttribute(tc.attribute)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if !bytes.Equal(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}
