package tth

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/cxmcc/tiger"
	gfile "github.com/guilt/gsum/pkg/file"
)

// ComputeHash computes the TigerTreeHash (TTH) of a file range.
func ComputeHash(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
	if key != "" {
		return "", fmt.Errorf("tth: keyed hashing not supported")
	}

	// Handle range specification
	var r io.Reader = reader
	var offset int64
	if rs.Start > 0 {
		if seeker, ok := reader.(io.Seeker); ok {
			_, err := seeker.Seek(rs.Start, io.SeekStart)
			if err != nil {
				return "", fmt.Errorf("seeking to start offset %d: %w", rs.Start, err)
			}
		} else {
			_, err := io.CopyN(io.Discard, reader, rs.Start)
			if err != nil {
				return "", fmt.Errorf("skipping to start offset %d: %w", rs.Start, err)
			}
		}
		offset = rs.Start
	}
	if rs.End != -1 {
		length := rs.End - rs.Start
		if length <= 0 {
			return "", fmt.Errorf("invalid range: start=%d, end=%d", rs.Start, rs.End)
		}
		r = io.LimitReader(reader, length)
	}

	// Read file in 1024-byte blocks
	const blockSize = 1024
	leaves := [][]byte{}
	buf := make([]byte, blockSize)
	var totalRead int64

	for {
		n, err := r.Read(buf)
		if n > 0 {
			// Compute Tiger hash for the block
			h := tiger.New()
			if _, err := h.Write(buf[:n]); err != nil {
				return "", fmt.Errorf("hashing block at offset %d: %w", totalRead+offset, err)
			}
			leaf := h.Sum(nil) // 24 bytes
			leaves = append(leaves, leaf)
			totalRead += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("reading range at offset %d: %w", totalRead+offset, err)
		}
	}

	if len(leaves) == 0 {
		// Empty file: return Tiger hash of empty string
		h := tiger.New()
		return hex.EncodeToString(h.Sum(nil)), nil
	}

	// Build Merkle tree
	for len(leaves) > 1 {
		var nextLevel [][]byte
		for i := 0; i < len(leaves); i += 2 {
			h := tiger.New()
			if _, err := h.Write(leaves[i]); err != nil {
				return "", fmt.Errorf("hashing internal node: %w", err)
			}
			if i+1 < len(leaves) {
				if _, err := h.Write(leaves[i+1]); err != nil {
					return "", fmt.Errorf("hashing internal node: %w", err)
				}
			}
			node := h.Sum(nil) // 24 bytes
			nextLevel = append(nextLevel, node)
		}
		leaves = nextLevel
	}

	return hex.EncodeToString(leaves[0]), nil
}
