//go:build !windows

package kernel

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func waitState(t *testing.T, s *Supervisor, want State) Status {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := s.Status()
		if st.State == want {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("state = %s, want %s", st.State, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRestartsAfterCrash(t *testing.T) {
	s := NewSupervisor()
	// Exits immediately, so the supervisor has to restart it.
	if err := s.Start(Spec{Path: "/bin/sh", Args: []string{"-c", "echo hello; exit 3"}}); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	waitState(t, s, Crashed)
	deadline := time.Now().Add(5 * time.Second)
	for s.Status().Restarts == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no restart after a crash")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !slices.Contains(s.Logs.Lines(), "hello") {
		t.Errorf("output not captured: %q", s.Logs.Lines())
	}
}

func TestStopEndsProcess(t *testing.T) {
	s := NewSupervisor()
	if err := s.Start(Spec{Path: "/bin/sh", Args: []string{"-c", "trap 'echo bye; exit 0' TERM; echo ready; while :; do sleep 0.05; done"}}); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, s, Running)
	if st.PID == 0 {
		t.Fatal("no pid")
	}
	// Signal only once the trap is installed.
	for deadline := time.Now().Add(5 * time.Second); !slices.Contains(s.Logs.Lines(), "ready"); {
		if time.Now().After(deadline) {
			t.Fatal("the test process never became ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.Stop()
	if got := s.Status(); got.State != Stopped || got.Restarts != 0 {
		t.Errorf("after Stop: %+v", got)
	}
	time.Sleep(200 * time.Millisecond)
	if s.Status().State != Stopped {
		t.Error("a stopped kernel must not be restarted")
	}
	if !slices.ContainsFunc(s.Logs.Lines(), func(l string) bool { return strings.Contains(l, "bye") }) {
		t.Errorf("the kernel should get a chance to exit cleanly: %q", s.Logs.Lines())
	}
}

func TestStartReplaces(t *testing.T) {
	s := NewSupervisor()
	defer s.Stop()
	for range 3 {
		if err := s.Start(Spec{Path: "/bin/sleep", Args: []string{"30"}}); err != nil {
			t.Fatal(err)
		}
	}
	if st := waitState(t, s, Running); st.Restarts != 0 {
		t.Errorf("replacing a process is not a crash: %+v", st)
	}
	if err := s.Start(Spec{Path: "/nonexistent"}); err == nil {
		t.Error("starting a missing binary must fail")
	}
}

func TestRing(t *testing.T) {
	r := NewRing(3)
	for _, l := range []string{"a", "b", "c", "d"} {
		r.Add(l)
	}
	if got := r.Lines(); !slices.Equal(got, []string{"b", "c", "d"}) {
		t.Errorf("Lines = %q", got)
	}
}
