package utils

import (
	"crypto/sha256"
	"encoding/hex"
)

// HashString takes an input string and returns its SHA256 hash as a hex-encoded string.
func HashString(input string) string {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}
