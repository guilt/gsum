package bcrypt

import (
	"crypto/sha512"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/emersion/go-bcrypt"
	gfile "github.com/guilt/gsum/pkg/file"
	"github.com/guilt/gsum/pkg/std"
)

// ComputeHash returns a bcrypt hash of the file range, using a deterministic salt derived from key+data.
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

	// Derive salt from key+data using SHA-512 (first 16 bytes)
	h := sha512.New()
	h.Write([]byte(key))
	h.Write(data)
	salt := h.Sum(nil)[:16]

	// Prepare input for bcrypt (max 8 bytes, padded to 72)
	input := key + string(data)
	if len(input) > 8 {
		input = input[:8]
	}
	inputBytes := make([]byte, 72)
	copy(inputBytes, input)
	copy(inputBytes[8:], h.Sum(nil))

	// Compute bcrypt hash
	hash, err := bcrypt.GenerateFromPasswordAndSalt(inputBytes, bcrypt.DefaultCost, salt)
	if err != nil {
		return "", err
	}

	// Return hash as string
	return string(hash), nil
}

// ParseChecksumLine parses a bcrypt checksum line, expecting format: <hash> [<byteCount>] <file[#range]>
func ParseChecksumLine(line string) (string, gfile.FileAndRangeSpec, int64, error) {
	parts := strings.Fields(line)
	if len(parts) < 2 || len(parts) > 3 {
		return "", gfile.FileAndRangeSpec{}, 0, fmt.Errorf("invalid bcrypt line: %s", line)
	}

	hashValue := parts[0]
	// Check valid bcrypt prefixes: $2$, $2a$, $2x$, $2y$, $2b$
	if !strings.HasPrefix(hashValue, "$2$") &&
		!strings.HasPrefix(hashValue, "$2a$") &&
		!strings.HasPrefix(hashValue, "$2x$") &&
		!strings.HasPrefix(hashValue, "$2y$") &&
		!strings.HasPrefix(hashValue, "$2b$") {
		return "", gfile.FileAndRangeSpec{}, 0, fmt.Errorf("invalid bcrypt hash: %s", hashValue)
	}

	var byteCount int64
	var fileIndex int
	if len(parts) == 3 {
		// Format: <hash> <byteCount> <file[#range]>
		bc, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return "", gfile.FileAndRangeSpec{}, 0, fmt.Errorf("invalid byte count: %s", parts[1])
		}
		byteCount = bc
		fileIndex = 2
	} else {
		// Format: <hash> <file[#range]>
		byteCount = 0
		fileIndex = 1
	}

	rs, err := gfile.ParseFilePath(parts[fileIndex])
	if err != nil {
		return "", gfile.FileAndRangeSpec{}, 0, fmt.Errorf("invalid file path: %w", err)
	}

	return hashValue, rs, byteCount, nil
}
