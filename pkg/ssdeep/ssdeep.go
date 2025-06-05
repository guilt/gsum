package ssdeep

import (
	"fmt"
	"io"

	"github.com/glaslos/ssdeep"
	gfile "github.com/guilt/gsum/pkg/file"
)

// ComputeHash generates an ssdeep fuzzy hash for a file range.
func ComputeHash(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
	if key != "" {
		return "", fmt.Errorf("ssdeep: keyed hashing not supported")
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

	// Read range for HashBytes
	data, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("reading range: %w", err)
	}

	hash, err := ssdeep.FuzzyBytes(data)
	if err != nil {
		return "", fmt.Errorf("computing ssdeep hash: %w", err)
	}

	return hash, nil
}
