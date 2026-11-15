package main

import (
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/xiongnemo/conch/internal/paths"
)

var (
	kernel32              = windows.NewLazySystemDLL("kernel32.dll")
	getConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	freeConsole           = kernel32.NewProc("FreeConsole")
)

// quietConsole closes the console window Windows opens for a command
// started at logon, and has it log to the file name in the data
// directory instead; started with no console at all, it logs there too.
// Run from a terminal, which other processes share, it keeps logging
// there.
func quietConsole(out io.Writer, name string) io.Writer {
	var pids [2]uint32
	if n, _, _ := getConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), 2); n > 1 {
		return out
	}
	freeConsole.Call()
	os.MkdirAll(paths.DataDir(), 0o700)
	f, err := os.OpenFile(filepath.Join(paths.DataDir(), name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return io.Discard
	}
	return f
}
