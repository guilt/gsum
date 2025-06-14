package scrypt

import (
	"crypto/sha512"
	"io"

	"golang.org/x/crypto/scrypt"

	"github.com/guilt/gsum/pkg/common"
	"github.com/guilt/gsum/pkg/hashers/std"
)

// ComputeHash returns a scrypt hash of the file range, salted with a SHA-512 hash of the key.
func ComputeHash(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
	rangeReader, err := std.PrepareRangeReader(reader, fileAndRangeSpec)
	if err != nil {
		return "", err
	}

	// Read all data from the range
	data, err := io.ReadAll(rangeReader)
	if err != nil {
		return "", err
	}

	// Derive salt from the key using SHA-512
	salt := sha512.Sum512([]byte(key))

	// Compute scrypt hash
	hash, err := scrypt.Key(append([]byte(key), data...), salt[:], 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

	// Return hash as hex string
	return std.BytesToHex(hash), nil
}
