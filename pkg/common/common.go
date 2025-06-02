package common

import (
	"fmt"
	_ "hash"
	"io"
	"strings"
)

// RangeSpec defines a range of bytes or percentages for hashing.
type RangeSpec struct {
	Start     int64
	End       int64
	IsPercent bool
}

// FileLifecycle defines callbacks for file hashing lifecycle events.
type FileLifecycle struct {
	OnStart func(offset1, offset2 int64)
	OnChunk func(bytes int64)
	OnEnd   func()
}

// LifecycleReader wraps a reader with lifecycle callbacks.
type LifecycleReader struct {
	Reader    io.Reader
	Lifecycle FileLifecycle
}

// Read implements io.Reader with lifecycle callbacks.
func (r *LifecycleReader) Read(p []byte) (n int, err error) {
	n, err = r.Reader.Read(p)
	if n > 0 {
		r.Lifecycle.OnChunk(int64(n))
	}
	return n, err
}

// Algorithm is an enumeration of supported hash algorithms.
type Algorithm int

const (
	CRC32 Algorithm = iota
	BSDCKSUM
	MD4
	MD5
	SHA1
	SHA256
	SHA512
	SHA3_256
	SHAKE128
	SHAKE256
	BLAKE2B
	BLAKE3
	HMACSHA1
	HMACSHA256
	HMACSHA512
	CHACHA20POLY1305
	XXHASH
	SIPHASH
	CITYHASH
	KANGAROOTWELVE
	STREEBOG256
	STREEBOG512
)

// Hasher defines a hashing algorithm's properties and behavior.
type Hasher struct {
	Algo              Algorithm
	Name              string
	Extension         string
	Keyed             bool
	Compute           func(reader io.Reader, rs RangeSpec, key string) (string, error)
	OutputLen         int
	Validate          func(key string) error
	AcceptsFile       func(fileName string) bool
	ParseChecksumLine func(line string) (hashValue, filePath string, rs RangeSpec, err error)
}

// hashers is the global map of supported hashers.
var hashers = make(map[Algorithm]Hasher)

// GetHasher retrieves a hasher by name.
func GetHasher(name string) (Hasher, error) {
	for _, h := range hashers {
		if strings.EqualFold(h.Name, name) {
			return h, nil
		}
	}
	return Hasher{}, fmt.Errorf("unsupported algorithm: %s", name)
}

// GetDefaultHashAlgorithm returns the default algorithm.
func GetDefaultHashAlgorithm() string {
	return "sha256"
}

// GetAllHasherNames returns all supported hasher names.
func GetAllHasherNames() []string {
	names := make([]string, 0, len(hashers))
	for _, h := range hashers {
		names = append(names, h.Name)
	}
	return names
}

// GetAllHashers returns all supported hashers.
func GetAllHashers() []Hasher {
	hashersList := make([]Hasher, 0, len(hashers))
	for _, h := range hashers {
		hashersList = append(hashersList, h)
	}
	return hashersList
}

// AddHasher adds a hasher to the global map.
func AddHasher(h Hasher) {
	hashers[h.Algo] = h
}
