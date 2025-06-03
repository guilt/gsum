package siphash

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/dchest/siphash"

	"github.com/guilt/gsum/pkg/common"
	gfile "github.com/guilt/gsum/pkg/file"
)

func ComputeHash(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
	if len(key) != 16 {
		return "", fmt.Errorf("key must be 16 bytes")
	}

	hash := siphash.New([]byte(key))

	if rs.Start != 0 || rs.End != 0 {
		file, ok := reader.(*common.LifecycleReader).Reader.(*os.File)
		if !ok {
			return "", fmt.Errorf("range-based hashing requires file reader")
		}

		var start, end int64
		fileInfo, err := file.Stat()
		if err != nil {
			return "", fmt.Errorf("cannot stat file: %s", err)
		}
		fileSize := fileInfo.Size()
		if rs.IsPercent {
			start = int64(float64(fileSize) * float64(rs.Start) / 10000)
			if rs.End == 0 {
				end = fileSize
			} else {
				end = int64(float64(fileSize) * float64(rs.End) / 10000)
			}
		} else {
			start = rs.Start
			if rs.End == 0 {
				end = fileSize
			} else {
				end = rs.End
			}
		}

		if _, err := file.Seek(start, io.SeekStart); err != nil {
			return "", fmt.Errorf("cannot seek: %s", err)
		}
		reader = io.LimitReader(file, end-start)
	}

	if _, err := io.Copy(hash, reader); err != nil {
		return "", fmt.Errorf("hashing error: %s", err)
	}

	sum := hash.Sum(nil)
	return hex.EncodeToString(sum), nil
}
