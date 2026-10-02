package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/xiongnemo/conch/internal/backend"
	"github.com/xiongnemo/conch/internal/backend/mihomo"
	"github.com/xiongnemo/conch/internal/backend/singbox"
	"github.com/xiongnemo/conch/internal/backend/xray"
	"github.com/xiongnemo/conch/internal/compile"
	"github.com/xiongnemo/conch/internal/daemon"
	"github.com/xiongnemo/conch/internal/diag"
	"github.com/xiongnemo/conch/internal/lists"
	"github.com/xiongnemo/conch/internal/model"
	"github.com/xiongnemo/conch/internal/paths"
	"github.com/xiongnemo/conch/internal/route"
	"github.com/xiongnemo/conch/internal/subscription"
)

var backends = map[string]backend.Router{
	"mihomo":   mihomo.Backend{},
	"xray":     xray.Backend{},
	"sing-box": singbox.Backend{},
}

func lookupBackend(name string) (backend.Router, error) {
	if b, ok := backends[name]; ok {
		return b, nil
	}
	return nil, fmt.Errorf("不认识的后端 %q（可以用 mihomo、xray 或 sing-box）", name)
}

// pipeline loads a profile with its subscriptions and compiles it.
type pipeline struct {
	profilePath string
	offline     bool
	log         io.Writer

	lists *lists.Store
}

// resolve fills in the default profile path.
func (pl *pipeline) resolve() error {
	p, err := resolveProfile(pl.profilePath)
	pl.profilePath = p
	return err
}

func (pl *pipeline) listLoader(ctx context.Context) backend.ListLoader {
	if pl.lists == nil {
		pl.lists = &lists.Store{Dir: paths.ListsDir(), Offline: pl.offline, Log: pl.log}
	}
	return func(p route.Provider) ([]lists.Entry, []string, error) {
		return pl.lists.Load(ctx, p)
	}
}

// compile returns the compiled profile, with the routes, nodes and chains
// of managed.yaml as the daemon adds them, and every diagnostic so far.
func (pl *pipeline) compile(ctx context.Context) (*compile.Result, diag.List, error) {
	p, err := model.Load(pl.profilePath)
	if err != nil {
		return nil, nil, err
	}
	if err := daemon.WithManaged(p, pl.profilePath); err != nil {
		return nil, nil, err
	}
	res, diags := pl.compileProfile(ctx, p)
	return res, diags, nil
}

// compileProfile compiles a loaded profile with its subscriptions.
func (pl *pipeline) compileProfile(ctx context.Context, p *model.Profile) (*compile.Result, diag.List) {
	subs := &subscription.Store{Dir: paths.SubscriptionsDir(), Offline: pl.offline, Log: pl.log}
	var diags diag.List
	snaps := map[string]*subscription.Snapshot{}
	for _, sub := range p.Subscriptions {
		snap, _, err := subs.Load(ctx, sub)
		if err != nil {
			diags.Errorf(sub.Pos, "%v", err)
			continue
		}
		snaps[sub.Name] = snap
	}
	subscription.Apply(p, snaps, &diags)
	res := compile.Compile(p)
	return res, append(diags, res.Diags...)
}

func newCompileCmd() *cobra.Command {
	var (
		pl           pipeline
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
			b, err := lookupBackend(backendName)
			if err != nil {
				return err
			}
			if err := pl.resolve(); err != nil {
				return err
			}
			pl.log = cmd.ErrOrStderr()
			res, diags, err := pl.compile(cmd.Context())
			if err != nil {
				return err
			}
			opts.Lists = pl.listLoader(cmd.Context())
			art, more := encode(res, b, opts, diags)
			printDiags(cmd.ErrOrStderr(), more)
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
	f.StringVarP(&pl.profilePath, "profile", "p", "", "profile 文件（默认是当前目录或配置目录里的 profile.yaml）")
	f.BoolVar(&pl.offline, "offline", false, "不下载订阅和规则列表，只用已缓存的")
	f.StringVarP(&outPath, "output", "o", "-", "输出文件，- 表示标准输出")
	f.StringVar(&manifestPath, "manifest", "", "同时输出 manifest（JSON）到这个文件")
	f.StringVar(&backendName, "backend", "mihomo", "内核后端：mihomo、xray 或 sing-box")
	f.StringVar(&opts.ControllerUnix, "controller-unix", "", "内核 API 的 unix socket 路径")
	f.StringVar(&opts.ControllerPipe, "controller-pipe", "", "内核 API 的 Windows 命名管道")
	f.StringVar(&opts.Controller, "controller", "", "内核 API 的 TCP 地址（仅用于调试）")
	return cmd
}

// encode checks and encodes a compiled profile. It returns a nil artifact
// when any diagnostic is an error.
func encode(res *compile.Result, b backend.Router, opts backend.Options, diags diag.List) (*backend.Artifact, diag.List) {
	diags = append(diags, backend.Check(res, b.Capabilities(), b.Name())...)
	if diags.HasErrors() {
		return nil, diags
	}
	art, more := b.Encode(res, opts)
	diags = append(diags, more...)
	if diags.HasErrors() {
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
