package bsdcksum

import (
	"fmt"
	"strconv"
	"strings"

	gfile "github.com/guilt/gsum/pkg/file"
	"github.com/guilt/gsum/pkg/log"
)

var logger = log.NewLogger()

func ParseChecksumLine(line string) (hashValue string, fileAndRange gfile.FileAndRangeSpec, byteCount int64, err error) {
	parts := strings.Fields(line)
	if len(parts) < 3 {
		logger.Errorf("Invalid cksum format: line=%s", line)
		return "", gfile.FileAndRangeSpec{}, 0, fmt.Errorf("invalid cksum format: %s", line)
	}
	hashValue = parts[0]
	count, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		logger.Errorf("Invalid byte count: count=%s", parts[1])
		return "", gfile.FileAndRangeSpec{}, 0, fmt.Errorf("invalid byte count: %s", parts[1])
	}
	filePath := strings.Join(parts[2:], " ")
	if err := fileAndRange.Parse(filePath); err != nil {
		logger.Errorf("Invalid file path: path=%s", filePath)
		return "", gfile.FileAndRangeSpec{}, 0, fmt.Errorf("invalid file path: %s", filePath)
	}
	fileAndRange.End = count
	return hashValue, fileAndRange, count, nil
}
