//go:build !windows

package main

import "io"

func quietAgent(out io.Writer) io.Writer { return out }
