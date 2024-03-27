package serde

import (
	"bytes"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func TestDeserializer_DeserializeAttribute(t *testing.T) {
	testCases := []struct {
		name     string
		data     []byte
		expected types.AttributeValue
		err      error
	}{
		{
			name:     "Binary",
			data:     []byte{0, byte(tagBinary), 0, 0, 0, 3, 1, 2, 3},
			expected: &types.AttributeValueMemberB{Value: []byte{1, 2, 3}},
		},
		{
			name:     "Number",
			data:     []byte{0, byte(tagNumber), 0, 0, 0, 5, 49, 46, 50, 51, 52},
			expected: &types.AttributeValueMemberN{Value: "1.234"},
		},
		{
			name:     "String",
			data:     []byte{0, byte(tagString), 0, 0, 0, 5, 104, 101, 108, 108, 111},
			expected: &types.AttributeValueMemberS{Value: "hello"},
		},
		{
			name:     "Boolean",
			data:     []byte{0, byte(tagBoolean), 1},
			expected: &types.AttributeValueMemberBOOL{Value: true},
		},
		{
			name:     "Null",
			data:     []byte{0, byte(tagNull)},
			expected: &types.AttributeValueMemberNULL{Value: true},
		},
		{
			name: "List",
			data: []byte{
				0, byte(tagList), 0, 0, 0, 2,
				0, byte(tagString), 0, 0, 0, 1, 97,
				0, byte(tagString), 0, 0, 0, 1, 98,
			},
			expected: &types.AttributeValueMemberL{Value: []types.AttributeValue{
				&types.AttributeValueMemberS{Value: "a"},
				&types.AttributeValueMemberS{Value: "b"},
			}},
		},
		{
			name: "Map",
			data: []byte{
				0, byte(tagMap), 0, 0, 0, 2,
				0, byte(tagString), 0, 0, 0, 3, 107, 101, 121,
				0, byte(tagString), 0, 0, 0, 5, 118, 97, 108, 117, 101,
				0, byte(tagString), 0, 0, 0, 4, 107, 101, 121, 50,
				0, byte(tagNumber), 0, 0, 0, 1, 50,
			},
			expected: &types.AttributeValueMemberM{Value: map[string]types.AttributeValue{
				"key":  &types.AttributeValueMemberS{Value: "value"},
				"key2": &types.AttributeValueMemberN{Value: "2"},
			}},
		},
		{
			name:     "Empty data",
			data:     []byte{},
			expected: nil,
			err:      errEmptySerializedData,
		},
		{
			name:     "Invalid tag",
			data:     []byte{0, 0xFF},
			expected: nil,
			err:      errInvalidTag,
		},
	}

	deserializer := NewDeserializer()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := deserializer.DeserializeAttribute(tc.data)
			if err != tc.err {
				if err == nil || tc.err == nil || err.Error() != tc.err.Error() {
					t.Errorf("Expected error '%v', got '%v'", tc.err, err)
				}
			}
			if !attributeEqual(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func attributeEqual(a, b types.AttributeValue) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return attributeValueEqual(a, b)
}

func attributeValueEqual(a, b types.AttributeValue) bool {
	switch av := a.(type) {
	case *types.AttributeValueMemberB:
		bv, ok := b.(*types.AttributeValueMemberB)
		return ok && bytes.Equal(av.Value, bv.Value)
	case *types.AttributeValueMemberN:
		bv, ok := b.(*types.AttributeValueMemberN)
		return ok && av.Value == bv.Value
	case *types.AttributeValueMemberS:
		bv, ok := b.(*types.AttributeValueMemberS)
		return ok && av.Value == bv.Value
	case *types.AttributeValueMemberBOOL:
		bv, ok := b.(*types.AttributeValueMemberBOOL)
		return ok && av.Value == bv.Value
	case *types.AttributeValueMemberNULL:
		bv, ok := b.(*types.AttributeValueMemberNULL)
		return ok && av.Value == bv.Value
	case *types.AttributeValueMemberL:
		bv, ok := b.(*types.AttributeValueMemberL)
		if !ok || len(av.Value) != len(bv.Value) {
			return false
		}
		for i := range av.Value {
			if !attributeValueEqual(av.Value[i], bv.Value[i]) {
				return false
			}
		}
		return true
	case *types.AttributeValueMemberM:
		bv, ok := b.(*types.AttributeValueMemberM)
		if !ok || len(av.Value) != len(bv.Value) {
			return false
		}
		for k, v := range av.Value {
			bvv, ok := bv.Value[k]
			if !ok || !attributeValueEqual(v, bvv) {
				return false
			}
		}
		return true
	case *types.AttributeValueMemberBS:
		bv, ok := b.(*types.AttributeValueMemberBS)
		if !ok || len(av.Value) != len(bv.Value) {
			return false
		}
		for i := range av.Value {
			if !bytes.Equal(av.Value[i], bv.Value[i]) {
				return false
			}
		}
		return true
	case *types.AttributeValueMemberNS:
		bv, ok := b.(*types.AttributeValueMemberNS)
		if !ok || len(av.Value) != len(bv.Value) {
			return false
		}
		for i := range av.Value {
			if av.Value[i] != bv.Value[i] {
				return false
			}
		}
		return true
	case *types.AttributeValueMemberSS:
		bv, ok := b.(*types.AttributeValueMemberSS)
		if !ok || len(av.Value) != len(bv.Value) {
			return false
		}
		for i := range av.Value {
			if av.Value[i] != bv.Value[i] {
				return false
			}
		}
		return true
	default:
		return false
	}
}
