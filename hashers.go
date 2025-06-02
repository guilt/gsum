package main

import (
	"bufio"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/siphash"
	"github.com/cespare/xxhash"
	"github.com/karalabe/k12"
	"github.com/streebog/streebog"
)

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

type Hasher struct {
	algo            Algorithm
	name            string
	extension       string
	keyed           bool
	hashFunc        func(key string) (hash.Hash, error)
	compute         func(reader io.Reader, rs RangeSpec, key string) (string, error)
	outputLen       int
	validate        func(key string) error
	acceptsFile     func(fileName string) bool
	parseChecksumLine func(line string) (hashValue, filePath string, rs RangeSpec, err error)
}

var hashers = map[Algorithm]Hasher{
	CRC32: {
		algo:      CRC32,
		name:      "crc32",
		extension: ".crc32",
		keyed:     false,
		hashFunc:  func(_ string) (hash.Hash, error) { return crc32.NewIEEE(), nil },
		compute:   std.Compute,
		outputLen: 8,
		validate:  func(_ string) error { return nil },
		acceptsFile: func(fileName string) bool {
			return strings.ToLower(filepath.Base(fileName)) == "crc32sum"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
	BSDCKSUM: {
		algo:      BSDCKSUM,
		name:      "bsd-cksum",
		extension: ".cksum",
		keyed:     false,
		hashFunc:  func(_ string) (hash.Hash, error) { return crc32.New(crc32.MakeTable(crc32.Castagnoli)), nil },
		compute:   std.Compute,
		outputLen: 8,
		validate:  func(_ string) error { return nil },
		acceptsFile: func(fileName string) bool {
			return strings.ToLower(filepath.Base(fileName)) == "cksum"
		},
		parseChecksumLine: func(line string) (hashValue, filePath string, rs RangeSpec, err error) {
			parts := strings.Fields(line)
			if len(parts) < 3 {
				return "", "", RangeSpec{}, fmt.Errorf("invalid cksum format: %s", line)
			}
			hashValue = parts[0]
			count, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return "", "", RangeSpec{}, fmt.Errorf("invalid byte count: %s", parts[1])
			}
			filePath = strings.Join(parts[2:], " ")
			rs = RangeSpec{start: 0, end: count}
			return hashValue, filePath, rs, nil
		},
	},
	MD4: {
		algo:      MD4,
		name:      "md4",
		extension: ".md4",
		keyed:     false,
		hashFunc:  func(_ string) (hash.Hash, error) { return md4.New(), nil },
		compute:   std.Compute,
		outputLen: 32,
		validate:  func(_ string) error { return nil },
		acceptsFile: func(fileName string) bool {
			return strings.ToLower(filepath.Base(fileName)) == "md4sum"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
	MD5: {
		algo:      MD5,
		name:      "md5",
		extension: ".md5",
		keyed:     false,
		hashFunc:  func(_ string) (hash.Hash, error) { return md5.New(), nil },
		compute:   std.Compute,
		outputLen: 32,
		validate:  func(_ string) error { return nil },
		acceptsFile: func(fileName string) bool {
			name := strings.ToLower(filepath.Base(fileName))
			return name == "md5sum" || name == "md5sums"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
	SHA1: {
		algo:      SHA1,
		name:      "sha1",
		extension: ".sha1",
		keyed:     false,
		hashFunc:  func(_ string) (hash.Hash, error) { return sha1.New(), nil },
		compute:   std.Compute,
		outputLen: 40,
		validate:  func(_ string) error { return nil },
		acceptsFile: func(fileName string) bool {
			name := strings.ToLower(filepath.Base(fileName))
			return name == "sha1sum" || name == "sha1sums" || name == "shasum"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
	SHA256: {
		algo:      SHA256,
		name:      "sha256",
		extension: ".sha256",
		keyed:     false,
		hashFunc:  func(_ string) (hash.Hash, error) { return sha256.New(), nil },
		compute:   std.Compute,
		outputLen: 64,
		validate:  func(_ string) error { return nil },
		acceptsFile: func(fileName string) bool {
			name := strings.ToLower(filepath.Base(fileName))
			return name == "sha256sum" || name == "sha256sums"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
	SHA512: {
		algo:      SHA512,
		name:      "sha512",
		extension: ".sha512",
		keyed:     false,
		hashFunc:  func(_ string) (hash.Hash, error) { return sha512.New(), nil },
		compute:   std.Compute,
		outputLen: 128,
		validate:  func(_ string) error { return nil },
		acceptsFile: func(fileName string) bool {
			name := strings.ToLower(filepath.Base(fileName))
			return name == "sha512sum" || name == "sha512sums"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
	SHA3_256: {
		algo:      SHA3_256,
		name:      "sha3-256",
		extension: ".sha3-256",
		keyed:     false,
		hashFunc:  func(_ string) (hash.Hash, error) { return sha3.New256(), nil },
		compute:   std.Compute,
		outputLen: 64,
		validate:  func(_ string) error { return nil },
		acceptsFile: func(fileName string) bool {
			return strings.ToLower(filepath.Base(fileName)) == "sha3-256sum"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
	SHAKE128: {
		algo:      SHAKE128,
		name:      "shake128",
		extension: ".shake128",
		keyed:     false,
		hashFunc:  func(_ string) (hash.Hash, error) { return sha3.NewShake128(), nil },
		compute:   shake.Compute,
		outputLen: 64,
		validate:  func(_ string) error { return nil },
		acceptsFile: func(fileName string) bool {
			return strings.ToLower(filepath.Base(fileName)) == "shake128sum"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
	SHAKE256: {
		algo:      SHAKE256,
		name:      "shake256",
		extension: ".shake256",
		keyed:     false,
		hashFunc:  func(_ string) (hash.Hash, error) { return sha3.NewShake256(), nil },
		compute:   shake.Compute,
		outputLen: 64,
		validate:  func(_ string) error { return nil },
		acceptsFile: func(fileName string) bool {
			return strings.ToLower(filepath.Base(fileName)) == "shake256sum"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
	BLAKE2B: {
		algo:      BLAKE2B,
		name:      "blake2b",
		extension: ".blake2b",
		keyed:     false,
		hashFunc:  func(_ string) (hash.Hash, error) { return blake2b.New256(nil) },
		compute:   std.Compute,
		outputLen: 64,
		validate:  func(_ string) error { return nil },
		acceptsFile: func(fileName string) bool {
			return strings.ToLower(filepath.Base(fileName)) == "blake2bsum"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
	BLAKE3: {
		algo:      BLAKE3,
		name:      "blake3",
		extension: ".blake3",
		keyed:     false,
		hashFunc:  func(_ string) (hash.Hash, error) { return blake3.New(), nil },
		compute:   std.Compute,
		outputLen: 64,
		validate:  func(_ string) error { return nil },
		acceptsFile: func(fileName string) bool {
			return strings.ToLower(filepath.Base(fileName)) == "blake3sum"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
	HMACSHA1: {
		algo:      HMACSHA1,
		name:      "hmac-sha1",
		extension: ".hmac-sha1",
		keyed:     true,
		hashFunc:  func(key string) (hash.Hash, error) { return hmac.New(sha1.New, []byte(key)), nil },
		compute:   std.Compute,
		outputLen: 40,
		validate:  func(key string) error { if key == "" { return fmt.Errorf("hmac-sha1 requires a key") }; return nil },
		acceptsFile: func(fileName string) bool {
			return strings.ToLower(filepath.Base(fileName)) == "hmac-sha1sum"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
	HMACSHA256: {
		algo:      HMACSHA256,
		name:      "hmac-sha256",
		extension: ".hmac-sha256",
		keyed:     true,
		hashFunc:  func(key string) (hash.Hash, error) { return hmac.New(sha256.New, []byte(key)), nil },
		compute:   std.Compute,
		outputLen: 64,
		validate:  func(key string) error { if key == "" { return fmt.Errorf("hmac-sha256 requires a key") }; return nil },
		acceptsFile: func(fileName string) bool {
			return strings.ToLower(filepath.Base(fileName)) == "hmac-sha256sum"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
	HMACSHA512: {
		algo:      HMACSHA512,
		name:      "hmac-sha512",
		extension: ".hmac-sha512",
		keyed:     true,
		hashFunc:  func(key string) (hash.Hash, error) { return hmac.New(sha512.New, []byte(key)), nil },
		compute:   std.Compute,
		outputLen: 128,
		validate:  func(key string) error { if key == "" { return fmt.Errorf("hmac-sha512 requires a key") }; return nil },
		acceptsFile: func(fileName string) bool {
			return strings.ToLower(filepath.Base(fileName)) == "hmac-sha512sum"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
	CHACHA20POLY1305: {
		algo:      CHACHA20POLY1305,
		name:      "chacha20-poly1305",
		extension: ".chacha20-poly1305",
		keyed:     true,
		hashFunc:  func(_ string) (hash.Hash, error) { return nil, fmt.Errorf("chacha20-poly1305 handled separately") },
		compute:   chacha.Compute,
		outputLen: 32,
		validate:  func(key string) error { if len(key) < 32 { return fmt.Errorf("chacha20-poly1305 requires a 32-byte key") }; return nil },
		acceptsFile: func(fileName string) bool {
			return strings.ToLower(filepath.Base(fileName)) == "chacha20-poly1305sum"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
	XXHASH: {
		algo:      XXHASH,
		name:      "xxhash",
		extension: ".xxhash",
		keyed:     false,
		hashFunc:  func(_ string) (hash.Hash, error) { return xxhash.New(), nil },
		compute:   std.Compute,
		outputLen: 16,
		validate:  func(_ string) error { return nil },
		acceptsFile: func(fileName string) bool {
			return strings.ToLower(filepath.Base(fileName)) == "xxhashsum"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
	SIPHASH: {
		algo:      SIPHASH,
		name:      "siphash",
		extension: ".siphash",
		keyed:     true,
		hashFunc:  func(key string) (hash.Hash, error) { if len(key) != 16 { return nil, fmt.Errorf("siphash requires a 16-byte key") }; return siphash.New([]byte(key)) },
		compute:   std.Compute,
		outputLen: 16,
		validate:  func(key string) error { if len(key) != 16 { return fmt.Errorf("siphash requires a 16-byte key") }; return nil },
		acceptsFile: func(fileName string) bool {
			return strings.ToLower(filepath.Base(fileName)) == "siphashsum"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
	CITYHASH: {
		algo:      CITYHASH,
		name:      "cityhash",
		extension: ".cityhash",
		keyed:     false,
		hashFunc:  func(_ string) (hash.Hash, error) { return cityhash.NewCityHash(), nil },
		compute:   std.Compute,
		outputLen: 16,
		validate:  func(_ string) error { return nil },
		acceptsFile: func(fileName string) bool {
			return strings.ToLower(filepath.Base(fileName)) == "cityhashsum"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
	KANGAROOTWELVE: {
		algo:      KANGAROOTWELVE,
		name:      "kangarootwelve",
		extension: ".kangarootwelve",
		keyed:     false,
		hashFunc:  func(_ string) (hash.Hash, error) { return k12.New(), nil },
		compute:   shake.Compute,
		outputLen: 64,
		validate:  func(_ string) error { return nil },
		acceptsFile: func(fileName string) bool {
			return strings.ToLower(filepath.Base(fileName)) == "kangarootwelvesum"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
	STREEBOG256: {
		algo:      STREEBOG256,
		name:      "streebog256",
		extension: ".streebog256",
		keyed:     false,
		hashFunc:  func(_ string) (hash.Hash, error) { return streebog.New256(), nil },
		compute:   std.Compute,
		outputLen: 64,
		validate:  func(_ string) error { return nil },
		acceptsFile: func(fileName string) bool {
			return strings.ToLower(filepath.Base(fileName)) == "streebog256sum"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
	STREEBOG512: {
		algo:      STREEBOG512,
		name:      "streebog512",
		extension: ".streebog512",
		keyed:     false,
		hashFunc:  func(_ string) (hash.Hash, error) { return streebog.New512(), nil },
		compute:   std.Compute,
		outputLen: 128,
		validate:  func(_ string) error { return nil },
		acceptsFile: func(fileName string) bool {
			return strings.ToLower(filepath.Base(fileName)) == "streebog512sum"
		},
		parseChecksumLine: standardParseChecksumLine,
	},
}

func (h Hasher) getHashes(hashFiles []string) map[string]string {
	hashes := make(map[string]string)
	for _, hashFile := range hashFiles {
		file, err := os.Open(hashFile)
		if err != nil {
			fmt.Printf("Error opening hash file %s: %v\n", hashFile, err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			hashValue, filePath, _, err := h.parseChecksumLine(line)
			if err != nil {
				for _, h2 := range hashers {
					hashValue, filePath, _, err = h2.parseChecksumLine(line)
					if err == nil {
						break
					}
				}
				if err != nil {
					fmt.Printf("Invalid checksum line in %s: %s: %v\n", hashFile, line, err)
					os.Exit(1)
				}
			}
			hashes[filePath] = hashValue
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading hash file %s: %v\n", hashFile, err)
			os.Exit(1)
		}
	}
	return hashes
}

func standardParseChecksumLine(line string) (hashValue, filePath string, rs RangeSpec, err error) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", "", RangeSpec{}, fmt.Errorf("invalid checksum format: %s", line)
	}
	hashValue = parts[0]
	filePath = strings.Join(parts[1:], " ")
	if strings.Contains(filePath, "#") {
		var err error
		filePath, rs, err = ParseFilePath(filePath)
		if err != nil {
			return "", "", RangeSpec{}, fmt.Errorf("invalid file path: %v", err)
		}
	}
	return hashValue, filePath, rs, nil
}

func GetDefaultHashAlgorithm() Algorithm {
	return SHA256
}

func GetHasher(name string) (Hasher, error) {
	for _, h := range hashers {
		if strings.EqualFold(h.name, name) {
			return h, nil
		}
	}
	return Hasher{}, fmt.Errorf("unsupported algorithm: %s", name)
}

func AddHasher(h Hasher) {
	hashers[h.algo] = h
}

func GetAllHasherNames() []string {
	names := make([]string, 0, len(hashers))
	for _, h := range hashers {
		names = append(names, h.name)
	}
	return names
}

func getHasherByName(name string) Hasher {
	for _, h := range hashers {
		if strings.EqualFold(h.name, name) {
			return h
		}
	}
	return Hasher{}
}