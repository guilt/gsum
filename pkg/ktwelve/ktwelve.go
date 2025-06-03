package ktwelve

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/mimoo/GoKangarooTwelve/K12"

	"github.com/guilt/gsum/pkg/common"
	gfile "github.com/guilt/gsum/pkg/file"
)

func ComputeHash(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
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
			return "", fmt.Errorf("failed to seek: %s", err)
		}
		reader = io.LimitReader(file, end-start)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("failed to read: %s", err)
	}

	hasher := K12.NewK12(nil)
	if _, err := hasher.Write(data); err != nil {
		return "", fmt.Errorf("failed to hash: %s", err)
	}

	hash := make([]byte, 32)
	if _, err := hasher.Read(hash); err != nil {
		return "", fmt.Errorf("failed to read hash: %s", err)
	}

	return hex.EncodeToString(hash), nil
}
