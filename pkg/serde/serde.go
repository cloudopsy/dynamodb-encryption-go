package serde

import (
	"encoding/binary"
	"fmt"
	"io"
)

const reserved = "\x00"

type Tag byte

const (
	tagBinary    Tag = 'b'
	tagNumber    Tag = 'n'
	tagString    Tag = 's'
	tagBoolean   Tag = '?'
	tagNull      Tag = 0
	tagList      Tag = 'L'
	tagMap       Tag = 'M'
	tagBinarySet Tag = 'B'
	tagNumberSet Tag = 'N'
	tagStringSet Tag = 'S'
)

func encodeLength(length int) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(length))
	return buf[:]
}

func encodeValue(value []byte) []byte {
	lengthBytes := encodeLength(len(value))
	encodedValue := make([]byte, len(lengthBytes)+len(value))
	copy(encodedValue, lengthBytes)
	copy(encodedValue[len(lengthBytes):], value)
	return encodedValue
}

func decodeLength(r io.Reader) (int, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return 0, err
	}
	return int(length), nil
}

func decodeValue(r io.Reader) ([]byte, error) {
	length, err := decodeLength(r)
	if err != nil {
		return nil, err
	}
	value := make([]byte, length)
	if _, err := io.ReadFull(r, value); err != nil {
		return nil, err
	}
	return value, nil
}

func decodeByte(r io.Reader) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

func decodeTag(r io.Reader) (Tag, error) {
	reserved, err := decodeByte(r)
	if err != nil {
		return 0, err
	}
	if reserved != 0 {
		return 0, fmt.Errorf("invalid tag: reserved byte is not null")
	}
	tag, err := decodeByte(r)
	if err != nil {
		return 0, err
	}
	return Tag(tag), nil
}

// type keyValue struct {
// 	key   string
// 	value types.AttributeValue
// }
