package siphash

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/dchest/siphash"

	"github.com/guilt/gsum/pkg/common"
	"github.com/guilt/gsum/pkg/std"
)

// ComputeHash computes the SipHash-2-4 of the file range with a 16-byte key.
func ComputeHash(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
	if len(key) != 16 {
		return "", fmt.Errorf("siphash: key must be 16 bytes")
	}

	rangeReader, err := std.PrepareRangeReader(reader, fileAndRangeSpec)
	if err != nil {
		return "", err
	}

	h := siphash.New([]byte(key))
	if _, err := io.Copy(h, rangeReader); err != nil {
		return "", fmt.Errorf("hashing error: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
