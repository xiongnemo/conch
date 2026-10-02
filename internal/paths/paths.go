// Package paths locates conch' configuration and data directories.
package paths

import (
	"os"
	"path/filepath"
	"runtime"
)

// ConfigDir holds user-edited files (profile.yaml, .env). On Unix it is
// always ~/.config/conch, including macOS, so it is easy to find.
func ConfigDir() string {
	if d := os.Getenv("CONCH_CONFIG_DIR"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" {
		if d, err := os.UserConfigDir(); err == nil {
			return filepath.Join(d, "conch")
		}
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" && runtime.GOOS == "linux" {
		return filepath.Join(d, "conch")
	}
	return filepath.Join(home(), ".config", "conch")
}

// DataDir holds downloaded kernels, caches and runtime state.
func DataDir() string {
	if d := os.Getenv("CONCH_DATA_DIR"); d != "" {
		return d
	}
	switch runtime.GOOS {
	case "windows":
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "conch")
		}
	case "darwin":
		return filepath.Join(home(), "Library", "Application Support", "conch")
	}
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "conch")
	}
	return filepath.Join(home(), ".local", "share", "conch")
}

// KernelHome is the working directory a kernel runs in (its -d), where it
// keeps geodata, rule-set caches and its own state.
func KernelHome(kernel string) string {
	return filepath.Join(DataDir(), "home", kernel)
}

// ListsDir caches rule lists that conch downloads on a kernel's behalf.
func ListsDir() string {
	return filepath.Join(DataDir(), "lists")
}

// SubscriptionsDir caches downloaded subscriptions.
func SubscriptionsDir() string {
	return filepath.Join(DataDir(), "subscriptions")
}

// UserDirs returns ConfigDir and DataDir for the user whose home is home,
// without environment overrides: for `sudo conch service install`,
// which sets things up for the user who ran sudo.
func UserDirs(home string) (configDir, dataDir string) {
	configDir = filepath.Join(home, ".config", "conch")
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(home, "AppData", "Roaming", "conch"), filepath.Join(home, "AppData", "Local", "conch")
	case "darwin":
		return configDir, filepath.Join(home, "Library", "Application Support", "conch")
	}
	return configDir, filepath.Join(home, ".local", "share", "conch")
}

func home() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "."
}
