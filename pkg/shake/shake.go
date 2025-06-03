package shake

import (
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/guilt/gsum/pkg/common"
	gfile "github.com/guilt/gsum/pkg/file"
)

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

		if start >= end || start < 0 || end <= 0 {
			return "", fmt.Errorf("invalid range: %d-%d", start, end)
		}

		if _, err := file.Seek(start, io.SeekStart); err != nil {
			return "", fmt.Errorf("cannot seek to start position: %s", err)
		}
		reader = io.LimitReader(file, end-start)
	}

	if _, err := io.Copy(h, reader); err != nil {
		return "", fmt.Errorf("error hashing data: %s", err)
	}

	out := make([]byte, 32)
	h.(io.Reader).Read(out)
	return hex.EncodeToString(out), nil
}
