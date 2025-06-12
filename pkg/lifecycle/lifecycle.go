package lifecycle

import (
	"fmt"

	"github.com/guilt/gsum/pkg/common"
	"github.com/schollz/progressbar/v3"
)

// ProgressFunc creates a FileLifecycle for a file range and size.
type ProgressFunc func(rs common.FileAndRangeSpec, size int64) common.FileLifecycle

// MakeDefaultLifecycle returns a no-op lifecycle matching the progressFunc signature.
func MakeDefaultLifecycle(rs common.FileAndRangeSpec, size int64) common.FileLifecycle {
	return common.FileLifecycle{
		OnStart: func(offset1, offset2 int64) {},
		OnChunk: func(bytes int64) {},
		OnEnd:   func() {},
	}
}

// MakeProgressBars returns a lifecycle with progress bar functionality.
func MakeProgressBars(rs common.FileAndRangeSpec, size int64) common.FileLifecycle {
	desc := fmt.Sprintf("Hashing %s", rs.String())
	bar := progressbar.DefaultBytes(size, desc)
	return common.FileLifecycle{
		OnStart: func(offset1, offset2 int64) {},
		OnChunk: func(bytes int64) {
			bar.Add64(bytes)
		},
		OnEnd: func() {
			bar.Close()
		},
	}
}
