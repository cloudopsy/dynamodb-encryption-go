package serde

import (
	"bytes"
	"fmt"
	"io"
	"sort"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type Deserializer struct{}

func NewDeserializer() *Deserializer {
	return &Deserializer{}
}

func (d *Deserializer) DeserializeAttribute(data []byte) (types.AttributeValue, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty serialized data")
	}
	r := bytes.NewReader(data)
	return d.deserialize(r)
}

func (d *Deserializer) deserializeBinary(r io.Reader) (types.AttributeValue, error) {
	value, err := decodeValue(r)
	if err != nil {
		return nil, err
	}
	return &types.AttributeValueMemberB{Value: value}, nil
}

func (d *Deserializer) deserializeNumber(r io.Reader) (types.AttributeValue, error) {
	value, err := decodeValue(r)
	if err != nil {
		return nil, err
	}
	return &types.AttributeValueMemberN{Value: string(value)}, nil
}

func (d *Deserializer) deserializeString(r io.Reader) (types.AttributeValue, error) {
	value, err := decodeValue(r)
	if err != nil {
		return nil, err
	}
	return &types.AttributeValueMemberS{Value: string(value)}, nil
}

func (d *Deserializer) deserializeBoolean(r io.Reader) (types.AttributeValue, error) {
	value, err := decodeByte(r)
	if err != nil {
		return nil, err
	}
	return &types.AttributeValueMemberBOOL{Value: value != 0}, nil
}

func (d *Deserializer) deserializeNull(r io.Reader) (types.AttributeValue, error) {
	return &types.AttributeValueMemberNULL{Value: true}, nil
}

func (d *Deserializer) deserializeList(r io.Reader) (types.AttributeValue, error) {
	memberCount, err := decodeLength(r)
	if err != nil {
		return nil, err
	}
	members := make([]types.AttributeValue, memberCount)
	for i := 0; i < memberCount; i++ {
		member, err := d.deserialize(r)
		if err != nil {
			return nil, err
		}
		members[i] = member
	}
	return &types.AttributeValueMemberL{Value: members}, nil
}

func (d *Deserializer) deserializeMap(r io.Reader) (types.AttributeValue, error) {
	memberCount, err := decodeLength(r)
	if err != nil {
		return nil, err
	}
	members := make(map[string]types.AttributeValue, memberCount)
	for i := 0; i < memberCount; i++ {
		key, err := d.deserialize(r)
		if err != nil {
			return nil, err
		}
		value, err := d.deserialize(r)
		if err != nil {
			return nil, err
		}
		keyStr, ok := key.(*types.AttributeValueMemberS)
		if !ok {
			return nil, fmt.Errorf("malformed serialized map: found %q as map key", key)
		}
		members[keyStr.Value] = value
	}
	return &types.AttributeValueMemberM{Value: members}, nil
}

func (d *Deserializer) deserializeBinarySet(r io.Reader) (types.AttributeValue, error) {
	memberCount, err := decodeLength(r)
	if err != nil {
		return nil, err
	}
	members := make([][]byte, memberCount)
	for i := 0; i < memberCount; i++ {
		member, err := decodeValue(r)
		if err != nil {
			return nil, err
		}
		members[i] = member
	}
	sort.Slice(members, func(i, j int) bool {
		return bytes.Compare(members[i], members[j]) < 0
	})
	return &types.AttributeValueMemberBS{Value: members}, nil
}

func (d *Deserializer) deserializeNumberSet(r io.Reader) (types.AttributeValue, error) {
	memberCount, err := decodeLength(r)
	if err != nil {
		return nil, err
	}
	members := make([]string, memberCount)
	for i := 0; i < memberCount; i++ {
		member, err := decodeValue(r)
		if err != nil {
			return nil, err
		}
		members[i] = string(member)
	}
	sort.Strings(members)
	return &types.AttributeValueMemberNS{Value: members}, nil
}

func (d *Deserializer) deserializeStringSet(r io.Reader) (types.AttributeValue, error) {
	memberCount, err := decodeLength(r)
	if err != nil {
		return nil, err
	}
	members := make([]string, memberCount)
	for i := 0; i < memberCount; i++ {
		member, err := decodeValue(r)
		if err != nil {
			return nil, err
		}
		members[i] = string(member)
	}
	sort.Strings(members)
	return &types.AttributeValueMemberSS{Value: members}, nil
}

func (d *Deserializer) deserializeFunction(tag Tag) (func(io.Reader) (types.AttributeValue, error), error) {
	switch tag {
	case tagBinary:
		return d.deserializeBinary, nil
	case tagNumber:
		return d.deserializeNumber, nil
	case tagString:
		return d.deserializeString, nil
	case tagBoolean:
		return d.deserializeBoolean, nil
	case tagNull:
		return d.deserializeNull, nil
	case tagList:
		return d.deserializeList, nil
	case tagMap:
		return d.deserializeMap, nil
	case tagBinarySet:
		return d.deserializeBinarySet, nil
	case tagNumberSet:
		return d.deserializeNumberSet, nil
	case tagStringSet:
		return d.deserializeStringSet, nil
	default:
		return nil, fmt.Errorf("invalid tag: reserved byte is not null")
	}
}

func (d *Deserializer) deserialize(r io.Reader) (types.AttributeValue, error) {
	tag, err := decodeTag(r)
	if err != nil {
		return nil, err
	}
	deserializeFunc, err := d.deserializeFunction(tag)
	if err != nil {
		return nil, err
	}
	return deserializeFunc(r)
}
