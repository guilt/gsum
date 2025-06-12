package pbkdf2

import (
	"crypto/sha512"
	"io"

	"github.com/guilt/gsum/pkg/common"
	"github.com/guilt/gsum/pkg/std"
	"golang.org/x/crypto/pbkdf2"
)

// ComputeHash derives a key from a file range with PBKDF2, using a deterministic SHA-512 salt and SHA-512 hash.
// ComputeHash returns a PBKDF2 hash of the file range, salted with a SHA-512 hash of the key.
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

	// Concatenate key and data for hashing
	input := append([]byte(key), data...)

	// Compute PBKDF2 hash
	hash := pbkdf2.Key(input, salt[:], 100000, 32, sha512.New)

	// Return hash as hex string
	return std.BytesToHex(hash), nil
}
