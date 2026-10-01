// Package paths locates nautilus' configuration and data directories.
package paths

import (
	"os"
	"path/filepath"
	"runtime"
)

// ConfigDir holds user-edited files (profile.yaml, .env). On Unix it is
// always ~/.config/nautilus, including macOS, so it is easy to find.
func ConfigDir() string {
	if d := os.Getenv("NAUTILUS_CONFIG_DIR"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" {
		if d, err := os.UserConfigDir(); err == nil {
			return filepath.Join(d, "nautilus")
		}
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" && runtime.GOOS == "linux" {
		return filepath.Join(d, "nautilus")
	}
	return filepath.Join(home(), ".config", "nautilus")
}

// DataDir holds downloaded kernels, caches and runtime state.
func DataDir() string {
	if d := os.Getenv("NAUTILUS_DATA_DIR"); d != "" {
		return d
	}
	switch runtime.GOOS {
	case "windows":
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "nautilus")
		}
	case "darwin":
		return filepath.Join(home(), "Library", "Application Support", "nautilus")
	}
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "nautilus")
	}
	return filepath.Join(home(), ".local", "share", "nautilus")
}

// KernelHome is the working directory a kernel runs in (its -d), where it
// keeps geodata, rule-set caches and its own state.
func KernelHome(kernel string) string {
	return filepath.Join(DataDir(), "home", kernel)
}

// ListsDir caches rule lists that nautilus downloads on a kernel's behalf.
func ListsDir() string {
	return filepath.Join(DataDir(), "lists")
}

func home() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "."
}
