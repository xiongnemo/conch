package main

import (
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"nautilus/internal/paths"
)

var (
	kernel32              = windows.NewLazySystemDLL("kernel32.dll")
	getConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	freeConsole           = kernel32.NewProc("FreeConsole")
)

// quietAgent closes the console window Windows opens for the agent when it
// starts at logon, and has it log to agent.log instead. Run from a
// terminal, which other processes share, it keeps logging there.
func quietAgent(out io.Writer) io.Writer {
	var pids [2]uint32
	if n, _, _ := getConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), 2); n != 1 {
		return out
	}
	freeConsole.Call()
	os.MkdirAll(paths.DataDir(), 0o700)
	f, err := os.OpenFile(filepath.Join(paths.DataDir(), "agent.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return io.Discard
	}
	return f
}
