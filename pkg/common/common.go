package common

import (
	"fmt"
	"io"
	"sort"
	"strings"

	gfile "github.com/guilt/gsum/pkg/file"
)

type FileLifecycle struct {
	OnStart func(offset1, offset2 int64)
	OnChunk func(bytes int64)
	OnEnd   func()
}

type LifecycleReader struct {
	Reader    io.Reader
	Lifecycle FileLifecycle
}

func (r *LifecycleReader) Read(p []byte) (n int, err error) {
	n, err = r.Reader.Read(p)
	if n > 0 {
		r.Lifecycle.OnChunk(int64(n))
	}
	return n, err
}

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
	SHA224
	SHA384
	SHA512_224
	SHA512_256
	SHA3_224
	SHA3_384
	SHA3_512
	RIPEMD160
	HMACMD5
	HMACRIPEMD160
	HMACBLAKE2B
	BLAKE2S
	ADLER32
)

type Hasher struct {
	Algo              Algorithm
	Name              string
	Extension         string
	Keyed             bool
	Compute           func(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error)
	OutputLen         int
	Validate          func(key string) error
	AcceptsFile       func(fileName string) bool
	ParseChecksumLine func(line string) (hashValue string, fileAndRange gfile.FileAndRangeSpec, byteCount int64, err error)
}

var hashers = make(map[Algorithm]Hasher)

func GetHasher(name string) (Hasher, error) {
	for _, h := range hashers {
		if strings.EqualFold(h.Name, name) {
			return h, nil
		}
	}
	return Hasher{}, fmt.Errorf("unsupported algorithm: %s", name)
}

func GetDefaultHashAlgorithm() string {
	return "sha256"
}

func GetAllHasherNames() []string {
	names := make([]string, 0, len(hashers))
	for _, h := range hashers {
		names = append(names, h.Name)
	}
	sort.Strings(names)
	return names
}

func GetAllHashers() []Hasher {
	hashersList := make([]Hasher, 0, len(hashers))
	for _, h := range hashers {
		hashersList = append(hashersList, h)
	}
	return hashersList
}

func AddHasher(h Hasher) {
	hashers[h.Algo] = h
}
