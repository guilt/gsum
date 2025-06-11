package siphash

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/dchest/siphash"

	gfile "github.com/guilt/gsum/pkg/file"
	"github.com/guilt/gsum/pkg/std"
)

// ComputeHash computes the SipHash-2-4 of the file range with a 16-byte key.
func ComputeHash(r io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
	if len(key) != 16 {
		return "", fmt.Errorf("siphash: key must be 16 bytes")
	}

	r, err := std.PrepareRangeReader(r, rs)
	if err != nil {
		return "", err
	}

	h := siphash.New([]byte(key))
	if _, err := io.Copy(h, r); err != nil {
		return "", fmt.Errorf("hashing error: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
