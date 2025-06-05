# gsum

`gsum` is a versatile command-line hashing tool written in Go, supporting a wide range of cryptographic and non-cryptographic hash algorithms. It offers advanced features like incremental hashing, GPG signing/verification, progress bars, and compatibility with existing Unix and Windows environments, making it ideal for developers, security enthusiasts, and system administrators.

## Features

- **Supported Algorithms**: CRC32, BSD-CKSUM, MD4, MD5, SHA1, SHA256, SHA512, SHA3-256, SHAKE128, SHAKE256, BLAKE2B, BLAKE3, HMAC-SHA1, HMAC-SHA256, HMAC-SHA512, ChaCha20-Poly1305, XXHash, SipHash, CityHash, KangarooTwelve.
- **Incremental Hashing**: Compute hashes for specific file ranges (e.g., 10%-20%) or incremental chunks.
- **GPG Support**: Sign and verify hash files with GPG for integrity and authenticity.
- **Progress Bars**: Visual feedback for long-running operations with customizable progress bars.
- **Keyed Hashing**: Support for algorithms requiring keys (e.g., HMAC, SipHash, ChaCha20-Poly1305).
- **Cross-Platform**: Compatible with modern OSes.
- **Modular Design**: Extensible architecture for adding new hash algorithms.

## Installation

**Go Installation**:

```shell
go install github.com/guilt/gsum/cmd/gsum@latest
```

## Usage

Run `gsum` with various flags to compute or verify hashes. Below are some examples:

### Compute a Hash and Verify

Hash a file (default is SHA256):
```shell
gsum example.txt
```

Verify a file:
```shell
gsum -verify example.txt.sha256 example.txt
```

### Advanced Usages

Hash a file and show a progress bar:
```shell
gsum -progress example.txt
```

Hash a file using Kangaroo12:
```shell
gsum -algo=kangaroo12 example.txt
```

Use SipHash with a 16-byte key:
```shell
gsum -algo=siphash -key=1234567890123456 example.txt
```

Hash a specific range (10%-20%) of a file:
```shell
gsum -progress example.txt#10%-20%
```

Compute hashes for 10% increments of a file:
```shell
gsum -algo=sha1 -increment=10% -progress example.txt
```

### Hash Verification

Verify a hash against a provided value as argument:
```shell
gsum -verify 80a3721188e40218b08b26776bc53bdae81e4784fff71d71450a197319cba113 example.txt
```

Verify checksums from a file:
```shell
gsum -verify=SHA256SUM example.txt
```

### GPG Signing and Verification

Sign a hash file with GPG:
```shell
gsum -output=SHA256SUM -gpg=SHA256SUM.asc example.txt
```

Verify a GPG-signed hash file:
```shell
gsum -verify=SHA256SUM -gpg=SHA256SUM.asc example.txt
```

### Full Help

List all supported algorithms and flags:
```shell
gsum -help
```

### Supported Algorithms

- **Adler-32**: Lightweight non-cryptographic checksum for data integrity.
- **ARGON2-SHA512**: Memory-hard password hash with SHA-512 salt, 2015 competition winner.
- **BCRYPT-SHA512**: Adaptive password hash with SHA-512 for secure storage.
- **BLAKE2B**: High-speed cryptographic hash for security and performance.
- **BLAKE2S**: Compact BLAKE2 variant for embedded systems.
- **BLAKE3**: Ultra-fast cryptographic hash for modern applications.
- **BSD-CKSUM**: Castagnoli polynomial-based checksum for data integrity.
- **ChaCha20-Poly1305**: Authenticated encryption with 32-byte key.
- **CityHash**: Non-cryptographic hash optimized for strings.
- **CRC32**: Fast, non-cryptographic checksum for error detection.
- **HMAC-BLAKE2B**: Keyed HMAC using BLAKE2B for high-speed authentication.
- **HMAC-MD5**: Keyed HMAC using MD5 for legacy authentication.
- **HMAC-RIPEMD160**: Keyed HMAC using RIPEMD160 for OpenPGP authentication.
- **HMAC-SHA1**: Keyed HMAC using SHA1 for authentication.
- **HMAC-SHA256**: Keyed HMAC using SHA256 for secure authentication.
- **HMAC-SHA512**: Keyed HMAC using SHA512 for high-security authentication.
- **Kangaroo12**: High-performance Keccak-based hash.
- **Keccak256**: Pre-SHA3 256-bit hash for Ethereum blockchain.
- **MD4**: Legacy cryptographic hash, less secure.
- **MD5**: Legacy cryptographic hash, widely used but vulnerable.
- **RIPEMD-160**: 160-bit cryptographic hash for OpenPGP and certificates.
- **SHA1**: Legacy Secure Hash Algorithm, used in older systems.
- **SHA224**: NIST-standard 224-bit SHA-2 hash for signatures and certificates.
- **SHA256**: Secure 256-bit SHA-2 hash for modern cryptography.
- **SHA3-224**: 224-bit SHA-3 hash, post-quantum secure for signatures.
- **SHA3-256**: Keccak-based 256-bit cryptographic hash.
- **SHA3-384**: 384-bit SHA-3 hash for high-security applications.
- **SHA3-512**: 512-bit SHA-3 hash for maximum security.
- **SHA384**: NIST-standard 384-bit SHA-2 hash for high-security applications.
- **SHA512**: Secure 512-bit SHA-2 hash for cryptography.
- **SHA512-224**: Truncated 224-bit SHA-2 hash for compact signatures.
- **SHA512-256**: Truncated 256-bit SHA-2 hash for efficiency and security.
- **SHAKE128**: Extendable-output function for flexible hashing.
- **SHAKE256**: Extendable-output function for secure hashing.
- **SipHash**: Keyed hash for hash tables with 16-byte key.
- **SM3**: Chinese 256-bit cryptographic hash for blockchain and standards.
- **Streebog**: Russian cryptographic hash for signatures and certificates.
- **TTH**: Tiger-based tree hash for BitTorrent and Gnutella file verification.
- **XXHash**: Non-cryptographic, high-speed hash for checksums.

## Development

To contribute or extend `gsum`:

1. **Add a New Algorithm**:
   - Create a new package under `pkg/` (e.g., `pkg/newalgo`).
   - Implement a `ComputeHash` function with the signature:
     ```go
     func ComputeHash(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error)
     ```
   - Register the algorithm in `pkg/hashers/hashers.go`.

2. **Build for a specific OS and architecture, such as Linux amd64**:
   ```shell
   GOOS=linux GOARCH=amd64 go build -o gsum-linux-amd64 ./cmd/gsum
   ```
3. **Run Tests**:
   (Tests TBD - Contributions welcome!)


## Dependencies

- `golang.org/x/crypto`: Most Crypto Algorithms
- `github.com/dchest/siphash`: SipHash
- `github.com/mimoo/GoKangarooTwelve`: KangarooTwelve
- `github.com/cespare/xxhash`: XXHash
- `github.com/zentures/cityhash`: CityHash
- `github.com/zeebo/blake3`: BLAKE3
- `github.com/schollz/progressbar/v3`: Progress bars
- `github.com/charmbracelet/log v0.4.2`: Color Logging

## License

MIT License. See [License](LICENSE.md) for details.

## Feedback

Built by [Vibe coding](https://en.wikipedia.org/wiki/Vibe_coding).

Pull requests, issues, and feature requests are welcome!
Vibe code it, Vibe debug it, Vibe test it, Vibe PR it, Vibe everything it.

* Author: [Grok 3.0](https://www.grok.com) and Debugger: Karthik Kumar Viswanathan
* Web   : http://karthikkumar.org
* Email : me@karthikkumar.org

Happy hashing!
