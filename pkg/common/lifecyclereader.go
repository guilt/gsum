package common

import "io"

// LifecycleReader is a reader that tracks the lifecycle of a file being processed.
type LifecycleReader struct {
	Reader    io.Reader
	Lifecycle FileLifecycle
}

// Read implements io.Reader.
func (lr *LifecycleReader) Read(parts []byte) (n int, err error) {
	n, err = lr.Reader.Read(parts)
	if n > 0 {
		lr.Lifecycle.OnChunk(int64(n))
	}
	return n, err
}
