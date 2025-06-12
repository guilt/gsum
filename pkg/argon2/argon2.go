package argon2

import (
	"crypto/sha512"
	"io"

	"github.com/guilt/gsum/pkg/common"
	"github.com/guilt/gsum/pkg/std"
	"golang.org/x/crypto/argon2"
)

// ComputeHash returns an Argon2id hash of the file range, salted with a SHA-512 hash of the key.
func ComputeHash(r io.Reader, key string, rs common.FileAndRangeSpec) (string, error) {
	// Prepare a reader for the requested range
	r, err := std.PrepareRangeReader(r, rs)
	if err != nil {
		return "", err
	}

	// Read all data from the range
	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}

	// Derive salt from the key using SHA-512
	salt := sha512.Sum512([]byte(key))

	// Concatenate key and data for hashing
	input := append([]byte(key), data...)

	// Compute Argon2id hash
	hash := argon2.IDKey(input, salt[:], 1, 64*1024, 4, 32)

	// Return hash as hex string
	return std.BytesToHex(hash), nil
}
