//go:build lite

package main

import (
	"os"
	"runtime/debug"
)

// Routers have little memory: unless GOMEMLIMIT says otherwise, the
// garbage collector works harder before conch grows past 48 MiB.
func init() {
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(48 << 20)
	}
}
