//go:build !windows

package main

import "io"

func quietConsole(out io.Writer, _ string) io.Writer { return out }
