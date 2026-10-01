package daemon

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// State is what the daemon remembers between runs, besides the profile:
// choices made in the UI and short-lived routes.
type State struct {
	Backend    string            `json:"backend,omitempty"`
	Selections map[string]string `json:"selections,omitempty"` // select group → member
	Mode       string            `json:"mode,omitempty"`       // overrides the profile's mode
	Temp       []TempRoute       `json:"temp,omitempty"`
	SysProxy   *SysProxyState    `json:"sysproxy,omitempty"`
}

// TempRoute is a manual route that expires, e.g. "this site via X for 2h".
type TempRoute struct {
	Key     string    `json:"key"`
	Via     string    `json:"via"`
	Expires time.Time `json:"expires"`
}

// SysProxyState remembers that nautilus set the system proxy, so a crash
// can be repaired on the next start.
type SysProxyState struct {
	Enabled  bool   `json:"enabled"`
	Previous string `json:"previous,omitempty"` // platform-specific snapshot
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
