package bcrypt

import (
	"crypto/sha512"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/emersion/go-bcrypt"
	gfile "github.com/guilt/gsum/pkg/file"
)

// ComputeHash hashes a file range with bcrypt, using a deterministic salt derived from key+data.
func ComputeHash(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
	if key == "" {
		return "", fmt.Errorf("bcrypt: key (password) is required")
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

	// Read the range data
	data, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("reading range: %w", err)
	}

	// Compute SHA-512 hash of key+data for salt and integrity
	h := sha512.New()
	if _, err := h.Write([]byte(key)); err != nil {
		return "", fmt.Errorf("hashing key: %w", err)
	}
	if _, err := h.Write(data); err != nil {
		return "", fmt.Errorf("hashing data: %w", err)
	}
	sha512Hash := h.Sum(nil) // 64 bytes

	// Derive deterministic 16-byte salt from SHA-512 hash
	salt := sha512Hash[:16]

	// Truncate key+data to 8 bytes
	input := key + string(data)
	if len(input) > 8 {
		input = input[:8]
	}

	// Create 72-byte input: 8-byte input + 64-byte SHA-512 hash
	inputBytes := make([]byte, 72)
	copy(inputBytes, input)
	copy(inputBytes[8:], sha512Hash)

	// Hash with bcrypt using deterministic salt
	bcryptHash, err := bcrypt.GenerateFromPasswordAndSalt(inputBytes, bcrypt.DefaultCost, salt)
	if err != nil {
		return "", fmt.Errorf("computing bcrypt hash: %w", err)
	}

	return string(bcryptHash), nil
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
