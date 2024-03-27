package serde

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

var (
	errInvalidTag          = errors.New("invalid tag: reserved byte is not null")
	errEmptySerializedData = errors.New("empty serialized data")
)

func TestEncodeLength(t *testing.T) {
	testCases := []struct {
		length   int
		expected []byte
	}{
		{0, []byte{0, 0, 0, 0}},
		{1, []byte{0, 0, 0, 1}},
		{255, []byte{0, 0, 0, 255}},
		{256, []byte{0, 0, 1, 0}},
		{65535, []byte{0, 0, 255, 255}},
	}

	for _, tc := range testCases {
		result := encodeLength(tc.length)
		if !bytes.Equal(result, tc.expected) {
			t.Errorf("encodeLength(%d) = %v, expected %v", tc.length, result, tc.expected)
		}
	}
}

func TestEncodeValue(t *testing.T) {
	testCases := []struct {
		value    []byte
		expected []byte
	}{
		{[]byte{}, []byte{0, 0, 0, 0}},
		{[]byte{1}, []byte{0, 0, 0, 1, 1}},
		{[]byte{1, 2, 3}, []byte{0, 0, 0, 3, 1, 2, 3}},
	}

	for _, tc := range testCases {
		result := encodeValue(tc.value)
		if !bytes.Equal(result, tc.expected) {
			t.Errorf("encodeValue(%v) = %v, expected %v", tc.value, result, tc.expected)
		}
	}
}

func TestDecodeLength(t *testing.T) {
	testCases := []struct {
		data     []byte
		expected int
		err      error
	}{
		{[]byte{0, 0, 0, 0}, 0, nil},
		{[]byte{0, 0, 0, 1}, 1, nil},
		{[]byte{0, 0, 0, 255}, 255, nil},
		{[]byte{0, 0, 1, 0}, 256, nil},
		{[]byte{0, 0, 255, 255}, 65535, nil},
		{[]byte{}, 0, io.EOF},
		{[]byte{0, 0, 0}, 0, io.ErrUnexpectedEOF},
	}

	for _, tc := range testCases {
		r := bytes.NewReader(tc.data)
		result, err := decodeLength(r)
		if err != tc.err {
			t.Errorf("decodeLength(%v) error = %v, expected %v", tc.data, err, tc.err)
		}
		if result != tc.expected {
			t.Errorf("decodeLength(%v) = %d, expected %d", tc.data, result, tc.expected)
		}
	}
}

func TestDecodeValue(t *testing.T) {
	testCases := []struct {
		data     []byte
		expected []byte
		err      error
	}{
		{[]byte{0, 0, 0, 0}, []byte{}, nil},
		{[]byte{0, 0, 0, 1, 1}, []byte{1}, nil},
		{[]byte{0, 0, 0, 3, 1, 2, 3}, []byte{1, 2, 3}, nil},
		{[]byte{}, nil, io.EOF},
		{[]byte{0, 0, 0, 1}, nil, io.EOF},
	}

	for _, tc := range testCases {
		r := bytes.NewReader(tc.data)
		result, err := decodeValue(r)
		if err != tc.err {
			t.Errorf("decodeValue(%v) error = %v, expected %v", tc.data, err, tc.err)
		}
		if !bytes.Equal(result, tc.expected) {
			t.Errorf("decodeValue(%v) = %v, expected %v", tc.data, result, tc.expected)
		}
	}
}

func TestDecodeTag(t *testing.T) {
	testCases := []struct {
		data     []byte
		expected Tag
		err      error
	}{
		{[]byte{0, byte(tagBinary)}, tagBinary, nil},
		{[]byte{0, byte(tagNumber)}, tagNumber, nil},
		{[]byte{0, byte(tagString)}, tagString, nil},
		{[]byte{0, byte(tagBoolean)}, tagBoolean, nil},
		{[]byte{0, byte(tagNull)}, tagNull, nil},
		{[]byte{0, byte(tagList)}, tagList, nil},
		{[]byte{0, byte(tagMap)}, tagMap, nil},
		{[]byte{0, byte(tagBinarySet)}, tagBinarySet, nil},
		{[]byte{0, byte(tagNumberSet)}, tagNumberSet, nil},
		{[]byte{0, byte(tagStringSet)}, tagStringSet, nil},
		{[]byte{1, byte(tagBinary)}, 0, errInvalidTag},
		{[]byte{}, 0, io.EOF},
		{[]byte{0}, 0, io.EOF},
	}

	for _, tc := range testCases {
		r := bytes.NewReader(tc.data)
		result, err := decodeTag(r)
		if err != tc.err {
			if err == nil || tc.err == nil || err.Error() != tc.err.Error() {
				t.Errorf("decodeTag(%v) error = %v, expected %v", tc.data, err, tc.err)
			}
		}
		if result != tc.expected {
			t.Errorf("decodeTag(%v) = %v, expected %v", tc.data, result, tc.expected)
		}
	}
}
