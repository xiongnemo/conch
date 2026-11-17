//go:build !windows

package main

import "io"

func quietConsole(out io.Writer, _ func() string) io.Writer { return out }
