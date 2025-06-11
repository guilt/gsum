package std

import (
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"

	gfile "github.com/guilt/gsum/pkg/file"
	"github.com/guilt/gsum/pkg/log"
)

var logger = log.NewLogger()

// PrepareRangeReader returns an io.Reader limited to the specified range in rs.
// If rs.Start/End are zero or -1, it returns the original reader.
func PrepareRangeReader(reader io.Reader, rs gfile.FileAndRangeSpec) (io.Reader, error) {
	var r io.Reader = reader
	// Only handle if range is specified
	if rs.Start > 0 {
		if seeker, ok := reader.(io.Seeker); ok {
			_, err := seeker.Seek(rs.Start, io.SeekStart)
			if err != nil {
				return nil, fmt.Errorf("seeking to start offset %d: %w", rs.Start, err)
			}
			// Do NOT assign seeker to r, since io.Seeker does not implement io.Reader
			// Just continue using the original reader after seeking
		} else {
			// If not seekable, skip bytes
			_, err := io.CopyN(io.Discard, r, rs.Start)
			if err != nil {
				return nil, fmt.Errorf("skipping to start offset %d: %w", rs.Start, err)
			}
		}
	}
	if rs.End != -1 && rs.End > rs.Start {
		length := rs.End - rs.Start
		if length <= 0 {
			return nil, fmt.Errorf("invalid range: start=%d, end=%d", rs.Start, rs.End)
		}
		r = io.LimitReader(r, length)
	}
	return r, nil
}

func ComputeHash(reader io.Reader, key string, hashFunc func(key string) (hash.Hash, error), rs gfile.FileAndRangeSpec) (string, error) {
	r, err := PrepareRangeReader(reader, rs)
	if err != nil {
		return "", err
	}

	h, err := hashFunc(key)
	if err != nil {
		return "", fmt.Errorf("cannot create hash: %s", err)
	}

	if _, err := io.Copy(h, r); err != nil {
		return "", fmt.Errorf("hashing error: %s", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func ParseChecksumLine(line string) (hashValue string, fileAndRange gfile.FileAndRangeSpec, byteCount int64, err error) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", gfile.FileAndRangeSpec{}, 0, fmt.Errorf("invalid checksum: %s", line)
	}

	hashValue = parts[0]
	fileStart := 1
	if len(parts) > 2 {
		if count, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
			byteCount = count
			fileStart = 2
		}
	}

	filePath := strings.Join(parts[fileStart:], " ")
	if err := fileAndRange.Parse(filePath); err != nil {
		return "", gfile.FileAndRangeSpec{}, 0, fmt.Errorf("invalid file: %s", filePath)
	}
	logger.Debugf("Parsed checksum: hash=%s, file=%s", hashValue, filePath)
	return hashValue, fileAndRange, byteCount, nil
}

// BytesToHex returns the hex encoding of a byte slice.
func BytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}
