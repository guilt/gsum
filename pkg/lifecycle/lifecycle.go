package lifecycle

import (
	"fmt"
	"path/filepath"

	"github.com/schollz/progressbar/v3"

	"github.com/guilt/gsum/pkg/common"
)

// DefaultLifecycle is a no-op lifecycle.
var DefaultLifecycle = common.FileLifecycle{
	OnStart: func(offset1, offset2 int64) {},
	OnChunk: func(bytes int64) {},
	OnEnd:   func() {},
}

// MakeDefaultLifecycle returns a no-op lifecycle matching the progressFunc signature.
func MakeDefaultLifecycle(filePath string, size, start, end int64) common.FileLifecycle {
	return DefaultLifecycle
}

// MakeProgressBars returns a lifecycle with progress bar functionality.
func MakeProgressBars(filePath string, size, start, end int64) common.FileLifecycle {
	var desc string
	if start == 0 && end == -1 {
		desc = fmt.Sprintf("Hashing %s", filepath.Base(filePath))
	} else {
		desc = fmt.Sprintf("Hashing %s#%d-%d", filepath.Base(filePath), start, end)
	}
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
