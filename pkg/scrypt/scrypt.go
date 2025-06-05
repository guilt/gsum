package scrypt

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"

	gfile "github.com/guilt/gsum/pkg/file"
	"golang.org/x/crypto/scrypt"
)

// ComputeHash derives a key from a file range with scrypt, using a deterministic SHA-512 salt from the key.
func ComputeHash(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
	if key == "" {
		return "", fmt.Errorf("scrypt-sha512: key (password) is required")
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

	// Scrypt with fixed parameters: N=2^15, r=8, p=1, output=64 bytes
	hash, err := scrypt.Key([]byte(key+string(data)), salt[:], 1<<15, 8, 1, 64)
	if err != nil {
		return "", fmt.Errorf("computing scrypt hash: %w", err)
	}
	return hex.EncodeToString(hash), nil
}
