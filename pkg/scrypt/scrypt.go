package scrypt

import (
	"crypto/sha512"
	gfile "github.com/guilt/gsum/pkg/file"
	"github.com/guilt/gsum/pkg/std"
	"golang.org/x/crypto/scrypt"
	"io"
)

// ComputeHash returns a scrypt hash of the file range, salted with a SHA-512 hash of the key.
func ComputeHash(r io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
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

	// Compute scrypt hash
	hash, err := scrypt.Key(append([]byte(key), data...), salt[:], 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

	// Return hash as hex string
	return std.BytesToHex(hash), nil
}
