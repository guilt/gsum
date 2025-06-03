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

		start, end, err := rs.ToBytes(fileSize)
		if err != nil {
			return "", fmt.Errorf("invalid range: %s", err)
		}

		if _, err := file.Seek(start, io.SeekStart); err != nil {
			return "", fmt.Errorf("cannot seek to start: %s", err)
		}
		reader = io.LimitReader(file, end-start)
		logger.Debugf("Computing hash: range=%d-%d", start, end)
	}

	if _, err := io.Copy(h, reader); err != nil {
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
