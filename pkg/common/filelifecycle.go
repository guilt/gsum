package common

import (
	"fmt"

	"github.com/schollz/progressbar/v3"
)

// FileLifecycle represents a lifecycle of a file being processed.
type FileLifecycle struct {
	OnStart func(offset1, offset2 int64)
	OnChunk func(bytes int64)
	OnEnd   func()
}

// ProgressFunc creates a FileLifecycle for a file range and size.
type ProgressFunc func(rs FileAndRangeSpec, size int64) FileLifecycle

// MakeDefaultLifecycle returns a no-op lifecycle matching the progressFunc signature.
func MakeDefaultLifecycle(rs FileAndRangeSpec, size int64) FileLifecycle {
	return FileLifecycle{
		OnStart: func(offset1, offset2 int64) {},
		OnChunk: func(bytes int64) {},
		OnEnd:   func() {},
	}
}

// MakeProgressBars returns a lifecycle with progress bar functionality.
func MakeProgressBars(rs FileAndRangeSpec, size int64) FileLifecycle {
	desc := fmt.Sprintf("Hashing %s", rs.String())
	bar := progressbar.DefaultBytes(size, desc)
	return FileLifecycle{
		OnStart: func(offset1, offset2 int64) {},
		OnChunk: func(bytes int64) {
			bar.Add64(bytes)
		},
		OnEnd: func() {
			bar.Close()
		},
	}
}
