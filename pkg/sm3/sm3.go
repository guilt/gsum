package sm3

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/emmansun/gmsm/sm3"
	gfile "github.com/guilt/gsum/pkg/file"
)

// ComputeHash computes the SM3 hash of a file range.
func ComputeHash(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
	if key != "" {
		return "", fmt.Errorf("sm3: keyed hashing not supported")
	}

	// Handle range specification
	var r io.Reader = reader
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
	}
	if rs.End != -1 {
		length := rs.End - rs.Start
		if length <= 0 {
			return "", fmt.Errorf("invalid range: start=%d, end=%d", rs.Start, rs.End)
		}
		r = io.LimitReader(reader, length)
	}

	// Compute SM3 hash
	h := sm3.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", fmt.Errorf("hashing range: %w", err)
	}
	hash := h.Sum(nil) // 32 bytes

	return hex.EncodeToString(hash), nil
}
