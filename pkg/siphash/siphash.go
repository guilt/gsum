package siphash

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/dchest/siphash"

	"github.com/guilt/gsum/pkg/common"
)

// Compute calculates the SipHash-2-4 hash for the given reader, respecting the RangeSpec.
func Compute(reader io.Reader, rs common.RangeSpec, key string) (string, error) {
	if len(key) != 16 {
		return "", fmt.Errorf("siphash requires a 16-byte key")
	}

	hash := siphash.New([]byte(key))

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

		if _, err := file.Seek(start, io.SeekStart); err != nil {
			return "", fmt.Errorf("cannot seek to start position: %v", err)
		}

		reader = io.LimitReader(file, end-start)
	}

	if _, err := io.Copy(hash, reader); err != nil {
		return "", fmt.Errorf("error hashing data: %v", err)
	}

	sum := hash.Sum(nil)
	return hex.EncodeToString(sum), nil
}
