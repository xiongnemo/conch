//go:build !windows

package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// serve runs a long-lived command until it is interrupted or terminated,
// as systemd and launchd stop services, or its terminal closes (SIGHUP):
// each way, it stops cleanly and puts the system proxy back.
func serve(ctx context.Context, out io.Writer, run func(context.Context, io.Writer) error) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	return run(ctx, out)
}
