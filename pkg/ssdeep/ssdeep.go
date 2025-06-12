package ssdeep

import (
	"fmt"
	"io"

	"github.com/glaslos/ssdeep"
	"github.com/guilt/gsum/pkg/common"
	"github.com/guilt/gsum/pkg/std"
)

// ComputeHash generates an ssdeep fuzzy hash for a file range. Keyed hashing not supported.
func ComputeHash(r io.Reader, key string, rs common.FileAndRangeSpec) (string, error) {
	if key != "" {
		return "", fmt.Errorf("ssdeep: keyed hashing not supported")
	}

	r, err := std.PrepareRangeReader(r, rs)
	if err != nil {
		return "", err
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}

	hash, err := ssdeep.FuzzyBytes(data)
	if err != nil {
		return "", err
	}
	return hash, nil
}
