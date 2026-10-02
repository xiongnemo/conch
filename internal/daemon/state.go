package daemon

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/xiongnemo/conch/internal/sidecar"
)

// State is what the daemon remembers between runs, besides the profile:
// choices made in the UI and short-lived routes.
type State struct {
	Backend    string            `json:"backend,omitempty"`
	Selections map[string]string `json:"selections,omitempty"` // select group → member
	Mode       string            `json:"mode,omitempty"`       // overrides the profile's mode
	TUN        *bool             `json:"tun,omitempty"`        // overrides the profile's tun.enable
	Temp       []TempRoute       `json:"temp,omitempty"`
	SysProxy   *SysProxyState    `json:"sysproxy,omitempty"`
	DNS        *DNSState         `json:"dns,omitempty"`
	// Sidecars keeps each sidecar's local ports, so the kernel config does
	// not change on every reload.
	Sidecars map[string]sidecar.Ports `json:"sidecars,omitempty"`
}

// DNSState remembers the system resolver settings conch replaced for
// TUN, so a crash can be repaired on the next start.
type DNSState struct {
	Applied  bool   `json:"applied"`
	Previous string `json:"previous,omitempty"`
}

// TempRoute is a manual route that expires, e.g. "this site via X for 2h".
type TempRoute struct {
	Key     string    `json:"key"`
	Via     string    `json:"via"`
	Expires time.Time `json:"expires"`
}

// SysProxyState remembers whether the user wants the system proxy and
// whether conch has set it, so a crash can be repaired on the next start.
type SysProxyState struct {
	Wanted   bool   `json:"wanted"`             // the user turned it on
	Applied  bool   `json:"applied"`            // the OS currently points at us
	Port     int    `json:"port,omitempty"`     // the port it points at
	Previous string `json:"previous,omitempty"` // settings before conch, to restore
}

func loadState(path string) (*State, error) {
	s := &State{Selections: map[string]string{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, err
	}
	if s.Selections == nil {
		s.Selections = map[string]string{}
	}
	return s, nil
}

func (s *State) save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".part"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// prune drops expired temporary routes and returns the next expiry.
func (s *State) prune(now time.Time) (next time.Time, changed bool) {
	kept := s.Temp[:0]
	for _, t := range s.Temp {
		if t.Expires.After(now) {
			kept = append(kept, t)
			if next.IsZero() || t.Expires.Before(next) {
				next = t.Expires
			}
		} else {
			changed = true
		}
	}
	s.Temp = kept
	return next, changed
}

// LastBackend returns the backend the daemon used last, or "mihomo".
func LastBackend(dataDir string) string {
	if st, err := loadState(filepath.Join(dataDir, "state.json")); err == nil && st.Backend != "" {
		return st.Backend
	}
	return "mihomo"
}

// SysProxyLeftover reports whether state.json says the system proxy still
// points at conch.
func SysProxyLeftover(dataDir string) (bool, int) {
	st, err := loadState(filepath.Join(dataDir, "state.json"))
	if err != nil || st.SysProxy == nil || !st.SysProxy.Applied {
		return false, 0
	}
	return true, st.SysProxy.Port
}
