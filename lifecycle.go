package main

import (
	"fmt"
	"path/filepath"
	"github.com/schollz/progressbar/v3"
)

type FileLifecycle struct {
	OnStart func(offset1, offset2 int64)
	OnChunk func(bytes int64)
	OnEnd   func()
}

var DefaultLifecycle = FileLifecycle{
	OnStart: func(offset1, offset2 int64) {},
	OnChunk: func(bytes int64) {},
	OnEnd:   func() {},
}

func MakeDefaultLifecycle() FileLifecycle {
	return DefaultLifecycle
}

func MakeProgressBars() func(filePath string, size, start, end int64) FileLifecycle {
	return func(filePath string, size, start, end int64) FileLifecycle {
		var desc string
		if start == 0 && end == -1 {
			desc = fmt.Sprintf("Hashing %s", filepath.Base(filePath))
		} else {
			desc = fmt.Sprintf("Hashing %s#%d-%d", filepath.Base(filePath), start, end)
		}
		bar := progressbar.DefaultBytes(size, desc)
		return FileLifecycle{
			OnStart: func(offset1, offset2 int64) {},
			OnChunk: func(bytes int64) {
				bar.Add64(bytes)
			},
			OnEnd: func() {
				bar.Finish()
			},
		}
	}
}