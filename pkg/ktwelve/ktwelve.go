package ktwelve

import (
	"crypto/sha512"
	gfile "github.com/guilt/gsum/pkg/file"
	"github.com/guilt/gsum/pkg/std"
	k12 "github.com/mimoo/GoKangarooTwelve/K12"
	"io"
)

// ComputeHash returns a KangarooTwelve hash of the file range, salted with a SHA-512 hash of the key.
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

	// Concatenate key and data for hashing
	input := append([]byte(key), data...)

	// Compute KangarooTwelve hash
	out := make([]byte, 32)
	k12.K12Sum(salt[:], input, out)

	// Return hash as hex string
	return std.BytesToHex(out), nil
}
