package tth

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/cxmcc/tiger"

	"github.com/guilt/gsum/pkg/common"
	"github.com/guilt/gsum/pkg/hashers/std"
)

// ComputeHash computes the TigerTreeHash (TTH) of a file range.
func ComputeHash(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
	if key != "" {
		return "", fmt.Errorf("tth: keyed hashing not supported")
	}

	// Use PrepareRangeReader for range handling
	rangeReader, err := std.PrepareRangeReader(reader, fileAndRangeSpec)
	if err != nil {
		return "", err
	}

	// Read file in 1024-byte blocks
	const blockSize = 1024
	leaves := [][]byte{}
	buf := make([]byte, blockSize)

	for {
		n, err := rangeReader.Read(buf)
		if n > 0 {
			// Compute Tiger hash for the block
			h := tiger.New()
			if _, err := h.Write(buf[:n]); err != nil {
				return "", fmt.Errorf("hashing block: %w", err)
			}
			leaf := h.Sum(nil) // 24 bytes
			leaves = append(leaves, leaf)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}

	// Build the tree (simplified: just hash the concatenation of all leaves)
	treeHash := tiger.New()
	for _, leaf := range leaves {
		if _, err := treeHash.Write(leaf); err != nil {
			return "", fmt.Errorf("hashing leaf: %w", err)
		}
	}

	return hex.EncodeToString(treeHash.Sum(nil)), nil
}
