package std

import (
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/guilt/gsum/pkg/common"
	gfile "github.com/guilt/gsum/pkg/file"
	"github.com/guilt/gsum/pkg/log"
)

var logger = log.NewLogger()

func Compute(reader io.Reader, key string, hashFunc func(key string) (hash.Hash, error), rs gfile.FileAndRangeSpec) (string, error) {
	h, err := hashFunc(key)
	if err != nil {
		return "", fmt.Errorf("cannot create hash: %s", err)
	}

	if rs.Start != 0 || rs.End != -1 {
		file, ok := reader.(*common.LifecycleReader).Reader.(*os.File)
		if !ok {
			return "", fmt.Errorf("range-based hashing requires a file reader")
		}
		fileInfo, err := file.Stat()
		if err != nil {
			return "", fmt.Errorf("cannot stat file: %s", err)
		}
		fileSize := fileInfo.Size()
		if fileSize == 0 {
			return "", fmt.Errorf("cannot hash empty file")
		}

		start := rs.Start
		end := rs.End
		if rs.IsPercent {
			start = int64(float64(fileSize) * float64(rs.Start) / 10000)
			if rs.End == -1 {
				end = fileSize
			} else {
				end = int64(float64(fileSize) * float64(rs.End) / 10000)
			}
		} else if rs.End == -1 {
			end = fileSize
		}

		logger.Debugf("std.Compute: fileSize=%d, range=%d-%d", fileSize, start, end)
		if start >= end || start < 0 || end <= 0 {
			return "", fmt.Errorf("invalid range: %d-%d", start, end)
		}

		if _, err := file.Seek(start, io.SeekStart); err != nil {
			return "", fmt.Errorf("cannot seek to start: %s", err)
		}
		reader = io.LimitReader(file, end-start)
	} else {
		logger.Debugf("std.Compute: hashing full file")
	}

	if _, err := io.Copy(h, reader); err != nil {
		return "", fmt.Errorf("error hashing data: %s", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func ParseChecksumLine(line string) (hashValue string, fileAndRange gfile.FileAndRangeSpec, byteCount int64, err error) {
	logger.Debugf("Parsing checksum line: %s", line)
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", gfile.FileAndRangeSpec{}, 0, fmt.Errorf("invalid checksum format: %s", line)
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
		return "", gfile.FileAndRangeSpec{}, 0, fmt.Errorf("invalid file path: %s", filePath)
	}
	return hashValue, fileAndRange, byteCount, nil
}
