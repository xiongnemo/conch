// Package kernel runs a kernel binary as a child process: it captures the
// output, restarts the kernel when it crashes, and makes sure the child
// does not outlive the daemon.
package kernel

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Spec says how to run a kernel.
type Spec struct {
	Path string
	Args []string
	Env  []string // added to the daemon's environment
	Dir  string
	// Clean lists files a killed process leaves behind that would stop
	// the next one, removed before every start: on Windows, a unix
	// socket's file outlives the process, and listening on it fails.
	Clean []string
	// PidFile records the running process, for KillOrphan after the
	// daemon died without stopping it.
	PidFile string
}

type State string

const (
	Stopped  State = "stopped"
	Starting State = "starting"
	Running  State = "running"
	Crashed  State = "crashed" // exited unexpectedly; a restart is pending
)

// Text names the state for people.
func (s State) Text() string {
	switch s {
	case Stopped:
		return "已停止"
	case Starting:
		return "启动中"
	case Running:
		return "运行中"
	case Crashed:
		return "已崩溃，正在重启"
	}
	return string(s)
}

// Status is a snapshot of the supervised process.
type Status struct {
	State    State     `json:"state"`
	PID      int       `json:"pid,omitempty"`
	Since    time.Time `json:"since"`
	Restarts int       `json:"restarts"`
	LastExit string    `json:"lastExit,omitempty"`
}

// Supervisor keeps one kernel process running.
type Supervisor struct {
	// OnLine receives every line the kernel prints and says whether to
	// keep it in Logs. It must not block.
	OnLine func(string) bool
	// OnRestart runs, in a goroutine of its own, each time the process
	// started again after it exited unexpectedly.
	OnRestart func()
	// Logs keeps the most recent lines.
	Logs *Ring

	mu      sync.Mutex
	gen     int // bumped by Start and Stop; stale restarts are dropped
	spec    Spec
	proc    *exec.Cmd
	exited  chan struct{}
	status  Status
	backoff time.Duration
}

func NewSupervisor() *Supervisor {
	return &Supervisor{Logs: NewRing(500), status: Status{State: Stopped}}
}

// Start runs spec, replacing any running process.
func (s *Supervisor) Start(spec Spec) error {
	s.Stop()
	s.mu.Lock()
	s.gen++
	gen := s.gen
	s.spec, s.backoff = spec, time.Second
	s.status = Status{State: Starting}
	s.mu.Unlock()
	return s.launch(gen)
}

func (s *Supervisor) launch(gen int) error {
	s.mu.Lock()
	spec := s.spec
	s.mu.Unlock()

	type result struct {
		cmd *exec.Cmd
		err error
	}
	started := make(chan result, 1)
	registered := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		// Pdeathsig is tied to the thread that started the child, so the
		// same locked thread starts the child and waits for it.
		runtime.LockOSThread()
		for _, f := range spec.Clean {
			os.Remove(f)
		}
		cmd := exec.Command(spec.Path, spec.Args...)
		cmd.Dir = spec.Dir
		cmd.Env = append(os.Environ(), spec.Env...)
		configureChild(cmd)
		pr, pw := io.Pipe()
		cmd.Stdout, cmd.Stderr = pw, pw
		if err := cmd.Start(); err != nil {
			started <- result{err: err}
			return
		}
		afterStart(cmd)
		if spec.PidFile != "" {
			os.WriteFile(spec.PidFile, fmt.Appendf(nil, "%d\n%s\n", cmd.Process.Pid, spec.Path), 0o600)
		}
		go s.pump(pr)
		started <- result{cmd: cmd}
		<-registered
		err := cmd.Wait()
		if spec.PidFile != "" {
			os.Remove(spec.PidFile)
		}
		pw.Close()
		close(exited)
		s.exitedWith(gen, err)
	}()

	r := <-started
	s.mu.Lock()
	if r.err != nil {
		s.status.State, s.status.LastExit = Stopped, r.err.Error()
		s.mu.Unlock()
		return fmt.Errorf("启动内核：%w", r.err)
	}
	if gen != s.gen { // stopped while starting
		s.mu.Unlock()
		close(registered)
		terminate(r.cmd)
		return errors.New("内核在启动过程中被停止")
	}
	s.proc, s.exited = r.cmd, exited
	s.status = Status{State: Running, PID: r.cmd.Process.Pid, Since: time.Now(), Restarts: s.status.Restarts, LastExit: s.status.LastExit}
	s.mu.Unlock()
	close(registered)
	return nil
}

// exitedWith records an unexpected exit and schedules a restart.
func (s *Supervisor) exitedWith(gen int, err error) {
	s.mu.Lock()
	if gen != s.gen {
		s.mu.Unlock()
		return // stopped or replaced on purpose
	}
	s.proc = nil
	s.status.State, s.status.PID, s.status.LastExit = Crashed, 0, exitText(err)
	s.mu.Unlock()
	s.restartLater(gen)
}

func (s *Supervisor) restartLater(gen int) {
	s.mu.Lock()
	delay := s.backoff
	s.backoff = min(s.backoff*2, time.Minute)
	last := s.status.LastExit
	s.mu.Unlock()
	s.line(fmt.Sprintf("[conch] 内核意外退出（%s），%s 后重启", last, delay))
	time.AfterFunc(delay, func() {
		s.mu.Lock()
		current := gen == s.gen
		if current {
			s.status.Restarts++
		}
		s.mu.Unlock()
		if !current {
			return
		}
		err := s.launch(gen)
		if err == nil && s.OnRestart != nil {
			go s.OnRestart()
		}
		if err != nil {
			s.line("[conch] " + err.Error())
			s.mu.Lock()
			current = gen == s.gen
			s.mu.Unlock()
			if current {
				s.restartLater(gen)
			}
		}
	})
}

// Stop terminates the process, waiting up to five seconds for a clean exit.
func (s *Supervisor) Stop() {
	s.mu.Lock()
	s.gen++
	proc, exited := s.proc, s.exited
	s.proc = nil
	s.status.State, s.status.PID = Stopped, 0
	s.mu.Unlock()
	if proc == nil {
		return
	}
	terminate(proc)
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		proc.Process.Kill()
		<-exited
	}
}

func (s *Supervisor) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// pump passes the kernel's lines on, cutting lines longer than 64 KiB to
// their start: it must keep reading, or the kernel blocks writing its log
// and never exits.
func (s *Supervisor) pump(r io.Reader) {
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		chunk, err := br.ReadSlice('\n')
		line := strings.TrimRight(string(chunk), "\r\n")
		for err == bufio.ErrBufferFull {
			_, err = br.ReadSlice('\n') // the rest of a long line
		}
		if line != "" || err == nil {
			s.line(line)
		}
		if err != nil {
			return
		}
	}
}

func (s *Supervisor) line(l string) {
	if s.OnLine == nil || s.OnLine(l) {
		s.Logs.Add(l)
	}
}

func exitText(err error) string {
	var ee *exec.ExitError
	switch {
	case err == nil:
		return "正常退出"
	case errors.As(err, &ee):
		return ee.ProcessState.String()
	default:
		return err.Error()
	}
}

// Ring keeps the last n lines.
type Ring struct {
	mu    sync.Mutex
	lines []string
	next  int
	full  bool
}

func NewRing(n int) *Ring { return &Ring{lines: make([]string, n)} }

func (r *Ring) Add(l string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines[r.next] = l
	r.next = (r.next + 1) % len(r.lines)
	r.full = r.full || r.next == 0
}

// Lines returns the kept lines, oldest first.
func (r *Ring) Lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.full {
		return append([]string(nil), r.lines[:r.next]...)
	}
	return append(append([]string(nil), r.lines[r.next:]...), r.lines[:r.next]...)
}
