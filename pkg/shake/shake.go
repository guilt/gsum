package shake

import (
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/guilt/gsum/pkg/common"
)

// Compute calculates the SHAKE hash for the given reader, respecting the RangeSpec.
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

	out := make([]byte, 32)
	h.(io.Reader).Read(out)
	return hex.EncodeToString(out), nil
}
