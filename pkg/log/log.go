package log

import (
	"os"

	"github.com/charmbracelet/log"
)

// NewLogger creates a new logger with level based on the DEBUG environment variable.
// If DEBUG is set (e.g., DEBUG=1), the level is DEBUG; otherwise, it's INFO.
// Logs are sent to os.Stderr.
func NewLogger() *log.Logger {
	logger := log.NewWithOptions(os.Stderr, log.Options{
		Level: log.InfoLevel,
	})

	if os.Getenv("DEBUG") != "" {
		logger.SetLevel(log.DebugLevel)
	}

	return logger
}
