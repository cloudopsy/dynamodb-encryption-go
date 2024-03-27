package serde

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type Serializer struct{}

func NewSerializer() *Serializer {
	return &Serializer{}
}

func (s *Serializer) SerializeAttribute(attribute types.AttributeValue) ([]byte, error) {
	switch v := attribute.(type) {
	case *types.AttributeValueMemberB:
		return s.serializeBinary(v.Value), nil
	case *types.AttributeValueMemberN:
		return s.serializeNumber(v.Value), nil
	case *types.AttributeValueMemberS:
		return s.serializeString(v.Value), nil
	case *types.AttributeValueMemberBOOL:
		return s.serializeBoolean(v.Value), nil
	case *types.AttributeValueMemberNULL:
		return s.serializeNull(), nil
	case *types.AttributeValueMemberL:
		return s.serializeList(v.Value), nil
	case *types.AttributeValueMemberM:
		return s.serializeMap(v.Value), nil
	case *types.AttributeValueMemberBS:
		return s.serializeBinarySet(v.Value), nil
	case *types.AttributeValueMemberNS:
		return s.serializeNumberSet(v.Value), nil
	case *types.AttributeValueMemberSS:
		return s.serializeStringSet(v.Value), nil
	default:
		return nil, fmt.Errorf("unsupported DynamoDB data type: %T", attribute)
	}
}

func (s *Serializer) serializeBinary(value []byte) []byte {
	return append([]byte{reserved[0], byte(tagBinary)}, encodeValue(value)...)
}

func (s *Serializer) serializeNumber(value string) []byte {
	return append([]byte{reserved[0], byte(tagNumber)}, encodeValue(s.transformNumberValue(value))...)
}

func (s *Serializer) serializeString(value string) []byte {
	return append([]byte{reserved[0], byte(tagString)}, encodeValue([]byte(value))...)
}

func (s *Serializer) serializeBoolean(value bool) []byte {
	var attributeValue byte
	if value {
		attributeValue = 1
	}
	return []byte{reserved[0], byte(tagBoolean), attributeValue}
}

func (s *Serializer) serializeNull() []byte {
	return []byte{reserved[0], byte(tagNull)}
}

func (s *Serializer) serializeList(value []types.AttributeValue) []byte {
	var buf bytes.Buffer
	buf.WriteByte(reserved[0])
	buf.WriteByte(byte(tagList))
	buf.Write(encodeLength(len(value)))

	for _, member := range value {
		serialized, err := s.SerializeAttribute(member)
		if err != nil {
			panic(err)
		}
		buf.Write(serialized)
	}

	return buf.Bytes()
}

func (s *Serializer) serializeMap(value map[string]types.AttributeValue) []byte {
	var buf bytes.Buffer
	buf.WriteByte(reserved[0])
	buf.WriteByte(byte(tagMap))
	buf.Write(encodeLength(len(value)))

	sortedItems := s.sortedKeyMap(value)
	for _, item := range sortedItems {
		buf.Write(s.serializeString(item.key))
		serialized, err := s.SerializeAttribute(item.value)
		if err != nil {
			panic(err)
		}
		buf.Write(serialized)
	}

	return buf.Bytes()
}

func (s *Serializer) serializeBinarySet(value [][]byte) []byte {
	return s.serializeSet(tagBinarySet, value, s.transformBinaryValue)
}

func (s *Serializer) serializeNumberSet(value []string) []byte {
	transformFunc := func(v interface{}) []byte {
		return s.transformNumberValue(v.(string))
	}
	return s.serializeSet(tagNumberSet, value, transformFunc)
}

func (s *Serializer) serializeStringSet(value []string) []byte {
	transformFunc := func(v interface{}) []byte {
		return []byte(v.(string))
	}
	return s.serializeSet(tagStringSet, value, transformFunc)
}

func (s *Serializer) serializeSet(tag Tag, value interface{}, transformFunc func(interface{}) []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(reserved[0])
	buf.WriteByte(byte(tag))

	var members [][]byte
	switch v := value.(type) {
	case [][]byte:
		buf.Write(encodeLength(len(v)))
		for _, member := range v {
			members = append(members, transformFunc(member))
		}
	case []string:
		buf.Write(encodeLength(len(v)))
		for _, member := range v {
			members = append(members, transformFunc(member))
		}
	default:
		panic(fmt.Sprintf("unsupported set type: %T", value))
	}

	sort.Slice(members, func(i, j int) bool {
		return bytes.Compare(members[i], members[j]) < 0
	})

	for _, member := range members {
		buf.Write(encodeValue(member))
	}

	return buf.Bytes()
}

func (s *Serializer) transformBinaryValue(value interface{}) []byte {
	return value.([]byte)
}

func (s *Serializer) transformNumberValue(value string) []byte {
	// Remove trailing zeros from the number
	num, err := strconv.ParseFloat(value, 64)
	if err != nil {
		panic(err)
	}
	return []byte(strconv.FormatFloat(num, 'f', -1, 64))
}

type keyValue struct {
	key   string
	value types.AttributeValue
}

func (s *Serializer) sortedKeyMap(m map[string]types.AttributeValue) []keyValue {
	var sortedItems []keyValue
	for key, value := range m {
		sortedItems = append(sortedItems, keyValue{key, value})
	}

	sort.Slice(sortedItems, func(i, j int) bool {
		return sortedItems[i].key < sortedItems[j].key
	})

	return sortedItems
}
