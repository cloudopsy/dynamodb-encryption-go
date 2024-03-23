package utils

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

type Compressor interface {
	Compress(data []byte) ([]byte, error)
	Decompress(data []byte) ([]byte, error)
}

type GzipCompressor struct {
	level int
}

func NewGzipCompressor(level int) *GzipCompressor {
	return &GzipCompressor{level: level}
}

type ZstdCompressor struct {
	level int
}

func NewZstdCompressor(level int) *ZstdCompressor {
	return &ZstdCompressor{level: level}
}

func compress(data []byte, fn func(w io.Writer) (io.WriteCloser, error)) ([]byte, error) {
	var buf bytes.Buffer
	w, err := fn(&buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create compressor: %v", err)
	}
	defer w.Close()

	_, err = w.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to compress data: %v", err)
	}

	err = w.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close compressor: %v", err)
	}

	return buf.Bytes(), nil
}

func decompress(data []byte, fn func(r io.Reader) ([]byte, error)) ([]byte, error) {
	return fn(bytes.NewReader(data))
}

func (c *GzipCompressor) Compress(data []byte) ([]byte, error) {
	return compress(data, func(w io.Writer) (io.WriteCloser, error) {
		return gzip.NewWriterLevel(w, c.level)
	})
}

func (c *GzipCompressor) Decompress(data []byte) ([]byte, error) {
	return decompress(data, func(r io.Reader) ([]byte, error) {
		reader, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %v", err)
		}
		defer reader.Close()

		decompressedData, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress data: %v", err)
		}

		return decompressedData, nil
	})
}

func (c *ZstdCompressor) Compress(data []byte) ([]byte, error) {
	return compress(data, func(w io.Writer) (io.WriteCloser, error) {
		return zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(c.level)))
	})
}

func (c *ZstdCompressor) Decompress(data []byte) ([]byte, error) {
	return decompress(data, func(r io.Reader) ([]byte, error) {
		decoder, err := zstd.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("failed to create zstd reader: %v", err)
		}
		defer decoder.Close()

		decompressedData, err := io.ReadAll(decoder)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress data: %v", err)
		}

		return decompressedData, nil
	})
}
