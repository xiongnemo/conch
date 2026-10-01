package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"path/filepath"

	"golang.org/x/sys/windows/svc"

	"nautilus/internal/paths"
	"nautilus/internal/platform/service"
)

// serve runs a long-lived command: under the service manager it answers
// its stop requests and logs to a file; otherwise until interrupted.
func serve(ctx context.Context, out io.Writer, run func(context.Context, io.Writer) error) error {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
		defer stop()
		return run(ctx, out)
	}
	log, err := os.OpenFile(filepath.Join(paths.ConfigDir(), "nautilus.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err == nil {
		defer log.Close()
		out = log
	}
	h := &handler{ctx: ctx, out: out, run: run}
	if err := svc.Run(service.Name, h); err != nil {
		return err
	}
	return h.err
}

type handler struct {
	ctx context.Context
	out io.Writer
	run func(context.Context, io.Writer) error
	err error
}

func (h *handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx, h.out) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			h.err = err
			status <- svc.Status{State: svc.Stopped}
			if err != nil {
				return true, 1
			}
			return false, 0
		case r := <-requests:
			switch r.Cmd {
			case svc.Interrogate:
				status <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
			}
		}
	}
}
