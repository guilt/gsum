package ssdeep

import (
	"fmt"
	"io"

	"github.com/glaslos/ssdeep"

	"github.com/guilt/gsum/pkg/common"
	"github.com/guilt/gsum/pkg/hashers/std"
)

// ComputeHash generates an ssdeep fuzzy hash for a file range. Keyed hashing not supported.
func ComputeHash(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
	if key != "" {
		return "", fmt.Errorf("ssdeep: keyed hashing not supported")
	}

	rangeReader, err := std.PrepareRangeReader(reader, fileAndRangeSpec)
	if err != nil {
		return "", err
	}

	data, err := io.ReadAll(rangeReader)
	if err != nil {
		return "", err
	}

	hash, err := ssdeep.FuzzyBytes(data)
	if err != nil {
		return "", err
	}
	return hash, nil
}
