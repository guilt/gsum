package bcrypt

import (
	"crypto/sha512"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/emersion/go-bcrypt"

	"github.com/guilt/gsum/pkg/common"
	"github.com/guilt/gsum/pkg/hashers/std"
)

// ComputeHash returns a bcrypt hash of the file range, using a deterministic salt derived from key+data.
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

	//Input Data for Keying
	keyData := append([]byte(key), data...)

	//Derive salt from the key using SHA-512
	salt := sha512.Sum512(keyData)

	// Prepare input for bcrypt (max 8 bytes, padded to 72)
	bcryptInput := append(keyData[:8], salt[:]...)

	// Compute bcrypt hash
	hash, err := bcrypt.GenerateFromPasswordAndSalt(bcryptInput, bcrypt.DefaultCost, salt[:16])
	if err != nil {
		return "", err
	}

	// Return hash as string
	return string(hash), nil
}

// ParseChecksumLine parses a bcrypt checksum line, expecting format: <hash> [<byteCount>] <file[#range]>
func ParseChecksumLine(line string) (string, common.FileAndRangeSpec, int64, error) {
	parts := strings.Fields(line)
	if len(parts) < 2 || len(parts) > 3 {
		return "", common.FileAndRangeSpec{}, 0, fmt.Errorf("invalid bcrypt line: %s", line)
	}

	hashValue := parts[0]
	// Check valid bcrypt prefixes: $2$, $2a$, $2x$, $2y$, $2b$
	if !strings.HasPrefix(hashValue, "$2$") &&
		!strings.HasPrefix(hashValue, "$2a$") &&
		!strings.HasPrefix(hashValue, "$2x$") &&
		!strings.HasPrefix(hashValue, "$2y$") &&
		!strings.HasPrefix(hashValue, "$2b$") {
		return "", common.FileAndRangeSpec{}, 0, fmt.Errorf("invalid bcrypt hash: %s", hashValue)
	}

	var byteCount int64
	var fileIndex int
	if len(parts) == 3 {
		// Format: <hash> <byteCount> <file[#range]>
		bc, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return "", common.FileAndRangeSpec{}, 0, fmt.Errorf("invalid byte count: %s", parts[1])
		}
		byteCount = bc
		fileIndex = 2
	} else {
		// Format: <hash> <file[#range]>
		byteCount = 0
		fileIndex = 1
	}

	var rs common.FileAndRangeSpec
	if err := rs.Parse(parts[fileIndex]); err != nil {
		return "", common.FileAndRangeSpec{}, 0, fmt.Errorf("invalid file path: %w", err)
	}

	return hashValue, rs, byteCount, nil
}
