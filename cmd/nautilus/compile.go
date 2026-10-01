package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"nautilus/internal/backend"
	"nautilus/internal/backend/mihomo"
	"nautilus/internal/compile"
	"nautilus/internal/diag"
	"nautilus/internal/model"
)

func newCompileCmd() *cobra.Command {
	var (
		profilePath  string
		outPath      string
		manifestPath string
		backendName  string
		opts         backend.Options
	)
	cmd := &cobra.Command{
		Use:   "compile",
		Short: "把 profile 编译成内核配置（不启动内核）",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if backendName != "mihomo" {
				return fmt.Errorf("暂时只支持 mihomo 后端")
			}
			p, err := model.Load(profilePath)
			if err != nil {
				return err
			}
			art, diags := build(p, mihomo.Backend{}, opts)
			printDiags(cmd.ErrOrStderr(), diags)
			if art == nil {
				return errReported
			}
			if err := writeOut(cmd.OutOrStdout(), outPath, art.Config); err != nil {
				return err
			}
			if manifestPath != "" {
				data, err := json.MarshalIndent(art.Manifest, "", "  ")
				if err != nil {
					return err
				}
				return os.WriteFile(manifestPath, append(data, '\n'), 0o644)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&profilePath, "profile", "p", "profile.yaml", "profile 文件")
	f.StringVarP(&outPath, "output", "o", "-", "输出文件，- 表示标准输出")
	f.StringVar(&manifestPath, "manifest", "", "同时输出 manifest（JSON）到这个文件")
	f.StringVar(&backendName, "backend", "mihomo", "内核后端")
	f.StringVar(&opts.ControllerUnix, "controller-unix", "", "内核 API 的 unix socket 路径")
	f.StringVar(&opts.ControllerPipe, "controller-pipe", "", "内核 API 的 Windows 命名管道")
	f.StringVar(&opts.Controller, "controller", "", "内核 API 的 TCP 地址（仅用于调试）")
	return cmd
}

// build compiles p for a backend. It returns a nil artifact when the
// diagnostics contain errors.
func build(p *model.Profile, b backend.Router, opts backend.Options) (*backend.Artifact, diag.List) {
	res := compile.Compile(p)
	diags := append(res.Diags, backend.Check(res, b.Capabilities(), b.Name())...)
	if diags.HasErrors() {
		return nil, diags
	}
	art, err := b.Encode(res, opts)
	if err != nil {
		diags.Errorf(diag.Pos{}, "%v", err)
		return nil, diags
	}
	return art, diags
}

func printDiags(w io.Writer, diags diag.List) {
	for _, d := range diags {
		fmt.Fprintln(w, d)
	}
}

func writeOut(stdout io.Writer, path string, data []byte) error {
	if path == "-" {
		_, err := stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
