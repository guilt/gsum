package argon2

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"

	gfile "github.com/guilt/gsum/pkg/file"
	"golang.org/x/crypto/argon2"
)

// ComputeHash derives a key from a file range with Argon2id, using a deterministic SHA-512 salt from the key.
func ComputeHash(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
	if key == "" {
		return "", fmt.Errorf("argon2: key (password) is required")
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

	// Derive salt from key using SHA-512
	salt := sha512.Sum512([]byte(key)) // 64 bytes

	// Argon2id with fixed parameters: time=1, memory=64MiB, threads=4, output=32 bytes
	hash := argon2.IDKey([]byte(key+string(data)), salt[:], 1, 64*1024, 4, 32)
	hashHex := hex.EncodeToString(hash)

	return hashHex, nil
}
