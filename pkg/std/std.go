package std

import (
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"

	"github.com/guilt/gsum/pkg/common"
	"github.com/guilt/gsum/pkg/file"
	"github.com/guilt/gsum/pkg/log"
)

// logger is the package-level logger for debug and error messages.
var logger = log.NewLogger()

// Compute calculates the hash for the given reader using the provided hasher's HashFunc, respecting the RangeSpec.
func Compute(reader io.Reader, rs common.RangeSpec, key string, hashFunc func(key string) (hash.Hash, error)) (string, error) {
	h, err := hashFunc(key)
	if err != nil {
		return "", fmt.Errorf("cannot create hash: %v", err)
	}

	if rs.Start != 0 || rs.End != -1 {
		file, ok := reader.(*common.LifecycleReader).Reader.(*os.File)
		if !ok {
			return "", fmt.Errorf("range-based hashing requires a file reader")
		}

		var start, end int64
		if rs.IsPercent {
			fileInfo, err := file.Stat()
			if err != nil {
				return "", fmt.Errorf("cannot stat file: %v", err)
			}
			fileSize := fileInfo.Size()
			if fileSize == 0 {
				return "", fmt.Errorf("cannot hash empty file")
			}
			start = int64(float64(fileSize) * float64(rs.Start) / 10000)
			if rs.End == -1 {
				end = fileSize
			} else {
				end = int64(float64(fileSize) * float64(rs.End) / 10000)
			}
		} else {
			start = rs.Start
			if rs.End == -1 {
				fileInfo, err := file.Stat()
				if err != nil {
					return "", fmt.Errorf("cannot stat file: %v", err)
				}
				end = fileInfo.Size()
			} else {
				end = rs.End
			}
		}

		if start >= end || start < 0 || end <= 0 {
			return "", fmt.Errorf("invalid range: %d-%d", start, end)
		}

		if _, err := file.Seek(start, io.SeekStart); err != nil {
			return "", fmt.Errorf("cannot seek to start position: %v", err)
		}

		reader = io.LimitReader(file, end-start)
	}

	if _, err := io.Copy(h, reader); err != nil {
		return "", fmt.Errorf("error hashing data: %v", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// ParseChecksumLine parses a standard checksum line in the format "<hash> <file>" or "<hash> <range> <file[#range>]".
func ParseChecksumLine(line string) (hashValue, filePath string, rs common.RangeSpec, err error) {
	logger.Debugf("Parsing checksum line: %s", line)
	parts := strings.Fields(line)
	if len(parts) < 2 {
		logger.Errorf("Invalid checksum format: line=%s", line)
		return "", "", common.RangeSpec{}, fmt.Errorf("invalid checksum format: %s", line)
	}

	hashValue = parts[0]
	filePath = parts[1]
	rs = common.RangeSpec{Start: 0, End: -1}

	if len(parts) > 2 {
		// Format: <hash> <range> <file#range> or <hash> <range> <file>
		filePath = strings.Join(parts[2:], " ")
	}

	if strings.Contains(filePath, "#") {
		filePath, rs, err = file.ParseFilePath(filePath)
		if err != nil {
			logger.Errorf("Invalid file path: path=%s, error=%v", filePath, err)
			return "", "", common.RangeSpec{}, fmt.Errorf("invalid file path: %v", err)
		}
	}

	return hashValue, filePath, rs, nil
}
