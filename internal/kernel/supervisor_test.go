//go:build !windows

package kernel

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

// What a killed process left behind is gone before every start, also the
// restarts after a crash.
func TestCleanBeforeStart(t *testing.T) {
	stale := filepath.Join(t.TempDir(), "kernel.sock")
	s := NewSupervisor()
	// Each run checks the file is gone, then leaves it behind and crashes.
	script := fmt.Sprintf(`test -e %[1]q && echo stale || echo clean; touch %[1]q; exit 1`, stale)
	os.WriteFile(stale, nil, 0o600)
	if err := s.Start(Spec{Path: "/bin/sh", Args: []string{"-c", script}, Clean: []string{stale}}); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	deadline := time.Now().Add(5 * time.Second)
	for s.Status().Restarts == 0 || len(s.Logs.Lines()) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("no restart after a crash")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if lines := s.Logs.Lines(); slices.Contains(lines, "stale") {
		t.Errorf("a start found the stale file: %q", lines)
	}
}

// OnRestart runs after restarts that follow a crash, not after Start.
func TestOnRestart(t *testing.T) {
	s := NewSupervisor()
	restarted := make(chan struct{}, 10)
	s.OnRestart = func() { restarted <- struct{}{} }
	if err := s.Start(Spec{Path: "/bin/sh", Args: []string{"-c", "exit 1"}}); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	select {
	case <-restarted:
	case <-time.After(5 * time.Second):
		t.Fatal("OnRestart did not run after a crash")
	}
	if n := s.Status().Restarts; n < 1 {
		t.Errorf("restarts = %d", n)
	}
}

// A line too long to keep is cut, and the lines after it still arrive:
// the kernel never blocks on its log.
func TestLongLogLine(t *testing.T) {
	s := NewSupervisor()
	script := `head -c 2097152 /dev/zero | tr '\0' x; echo; echo after; exec sleep 30`
	if err := s.Start(Spec{Path: "/bin/sh", Args: []string{"-c", script}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !slices.Contains(s.Logs.Lines(), "after") {
		if time.Now().After(deadline) {
			t.Fatalf("the line after a 2 MiB one never arrived")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if lines := s.Logs.Lines(); len(lines[0]) != 64*1024-1 && len(lines[0]) != 64*1024 {
		t.Errorf("long line kept as %d bytes", len(lines[0]))
	}
	stopped := make(chan struct{})
	go func() { s.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop hung")
	}
}

// A kernel a dead daemon left running is ended; a process that only has
// its pid now is not.
func TestKillOrphan(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip(err)
	}
	orphan := exec.Command(sleep, "60")
	if err := orphan.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { orphan.Wait(); close(exited) }()
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "k.pid")
	os.WriteFile(pidFile, fmt.Appendf(nil, "%d\n%s\n", orphan.Process.Pid, sleep), 0o600)
	if !KillOrphan(pidFile) {
		t.Fatal("the orphan was not ended")
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("the orphan still runs")
	}
	// Another binary under the recorded pid: this test itself.
	os.WriteFile(pidFile, fmt.Appendf(nil, "%d\n%s\n", os.Getpid(), sleep), 0o600)
	if KillOrphan(pidFile) {
		t.Error("ended a process that is not the recorded kernel")
	}
}

// The supervisor records the running process and forgets it when it ends.
func TestPidFile(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "k.pid")
	s := NewSupervisor()
	if err := s.Start(Spec{Path: "/bin/sh", Args: []string{"-c", "sleep 30"}, PidFile: pidFile}); err != nil {
		t.Fatal(err)
	}
	if pid, _, ok := readPidFile(pidFile); !ok || pid != s.Status().PID {
		t.Fatalf("pid file says %d, the kernel is %d", pid, s.Status().PID)
	}
	s.Stop()
	if _, err := os.Stat(pidFile); err == nil {
		t.Error("the pid file stayed after Stop")
	}
}
