package ktwelve

import (
	"crypto/sha512"
	"io"

	k12 "github.com/mimoo/GoKangarooTwelve/K12"

	"github.com/guilt/gsum/pkg/common"
	"github.com/guilt/gsum/pkg/hashers/std"
)

// ComputeHash returns a KangarooTwelve hash of the file range, salted with a SHA-512 hash of the key.
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

	// Compute KangarooTwelve hash
	out := make([]byte, 32)
	k12.K12Sum(salt[:], input, out)

	// Return hash as hex string
	return std.BytesToHex(out), nil
}
