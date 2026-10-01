package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"nautilus/internal/backend"
	"nautilus/internal/backend/mihomo"
	"nautilus/internal/backend/xray"
	"nautilus/internal/compile"
	"nautilus/internal/diag"
	"nautilus/internal/lists"
	"nautilus/internal/model"
	"nautilus/internal/paths"
	"nautilus/internal/route"
)

var backends = map[string]backend.Router{
	"mihomo": mihomo.Backend{},
	"xray":   xray.Backend{},
}

func newCompileCmd() *cobra.Command {
	var (
		profilePath  string
		outPath      string
		manifestPath string
		backendName  string
		offline      bool
		opts         backend.Options
	)
	cmd := &cobra.Command{
		Use:   "compile",
		Short: "把 profile 编译成内核配置（不启动内核）",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, ok := backends[backendName]
			if !ok {
				return fmt.Errorf("不认识的后端 %q（可以用 mihomo 或 xray）", backendName)
			}
			p, err := model.Load(profilePath)
			if err != nil {
				return err
			}
			store := &lists.Store{Dir: paths.ListsDir(), Offline: offline, Log: cmd.ErrOrStderr()}
			opts.Lists = func(pv route.Provider) ([]lists.Entry, []string, error) {
				return store.Load(cmd.Context(), pv)
			}
			art, diags := build(p, b, opts)
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
	f.StringVar(&backendName, "backend", "mihomo", "内核后端：mihomo 或 xray")
	f.BoolVar(&offline, "offline", false, "不下载规则列表，只用已缓存的")
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
	art, encDiags := b.Encode(res, opts)
	return art, append(diags, encDiags...)
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
