package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/xiongnemo/conch/internal/backend"
	"github.com/xiongnemo/conch/internal/daemon"
	"github.com/xiongnemo/conch/internal/diag"
	"github.com/xiongnemo/conch/internal/model"
	"github.com/xiongnemo/conch/internal/paths"
)

func newEditCmd() *cobra.Command {
	var pl pipeline
	cmd := &cobra.Command{
		Use:   "edit",
		Short: "用编辑器修改 profile.yaml，保存前先检查",
		Long: `用 $VISUAL 或 $EDITOR 打开 profile.yaml 的一份副本。保存并退出编辑器后，conch 先检查它：
有错误就带着错误说明重新打开，没有错误才写回 profile.yaml，正在运行的 daemon 会自动应用。
想放弃修改，清空文件再保存即可。`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := pl.resolve(); err != nil {
				return err
			}
			pl.offline = true // check against what is cached; never wait for downloads
			pl.log = cmd.ErrOrStderr()
			return editProfile(cmd, &pl)
		},
	}
	cmd.Flags().StringVarP(&pl.profilePath, "profile", "p", "", "profile 文件（默认是当前目录或配置目录里的 profile.yaml）")
	return cmd
}

func editProfile(cmd *cobra.Command, pl *pipeline) error {
	path := pl.profilePath
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp("", "conch-profile-*.yaml")
	if err != nil {
		return err
	}
	tmp := f.Name()
	f.Close()
	defer os.Remove(tmp)

	content, header := original, []string(nil)
	for {
		if err := os.WriteFile(tmp, append([]byte(strings.Join(header, "")), content...), 0o600); err != nil {
			return err
		}
		if err := runEditor(tmp); err != nil {
			return err
		}
		edited, err := os.ReadFile(tmp)
		if err != nil {
			return err
		}
		content = stripHeader(edited)
		switch {
		case len(bytes.TrimSpace(content)) == 0:
			fmt.Fprintln(cmd.OutOrStdout(), "文件是空的，已放弃修改")
			return nil
		case bytes.Equal(content, original):
			fmt.Fprintln(cmd.OutOrStdout(), "没有修改")
			return nil
		}
		diags, err := checkProfile(cmd.Context(), pl, path, content)
		if err != nil {
			diags = diag.List{{Severity: diag.Error, Msg: err.Error()}}
		}
		if !diags.HasErrors() {
			if err := writeInPlace(path, content); err != nil {
				return err
			}
			printDiags(cmd.ErrOrStderr(), diags) // warnings
			fmt.Fprintf(cmd.OutOrStdout(), "已保存 %s；正在运行的 daemon 会自动应用\n", path)
			return nil
		}
		header = errorHeader(diags)
	}
}

// headerMark starts each line conch puts above the profile; they are
// removed before the profile is checked and saved.
const headerMark = "#> "

func errorHeader(diags diag.List) []string {
	var errs []diag.Diagnostic
	for _, d := range diags {
		if d.Severity == diag.Error {
			errs = append(errs, d)
		}
	}
	lines := []string{
		headerMark + "conch：这份 profile 有错误，还没有保存。改好后保存并退出编辑器；\n",
		headerMark + "想放弃修改，清空文件再保存。以 #> 开头的这几行会自动去掉。\n",
	}
	offset := len(lines) + len(errs) + 1 // line numbers as shown in the editor
	for _, d := range errs {
		where := ""
		if d.Pos.Line > 0 {
			where = fmt.Sprintf("第 %d 行：", d.Pos.Line+offset)
		}
		lines = append(lines, headerMark+"  "+where+d.Msg+"\n")
	}
	return append(lines, headerMark+"\n")
}

func stripHeader(data []byte) []byte {
	for bytes.HasPrefix(data, []byte(headerMark)) || bytes.HasPrefix(data, []byte(strings.TrimSpace(headerMark)+"\n")) {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			return nil
		}
		data = data[i+1:]
	}
	return data
}

// checkProfile compiles content as the daemon would, with managed.yaml
// and for the kernel the daemon used last.
func checkProfile(ctx context.Context, pl *pipeline, path string, content []byte) (diag.List, error) {
	p, err := model.Parse(content, path)
	if err != nil {
		return nil, err
	}
	if err := daemon.WithManaged(p, path); err != nil {
		return nil, err
	}
	res, diags := pl.compileProfile(ctx, p)
	b, err := lookupBackend(cmpOr(daemon.LastBackend(paths.DataDir()), "mihomo"))
	if err != nil {
		return nil, err
	}
	_, diags = encode(res, b, backend.Options{Lists: pl.listLoader(ctx)}, diags)
	return diags, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func runEditor(file string) error {
	editor := cmpOr(os.Getenv("VISUAL"), os.Getenv("EDITOR"))
	if editor == "" {
		editor = "vi"
		if runtime.GOOS == "windows" {
			editor = "notepad"
		}
	}
	args := strings.Fields(editor) // e.g. "code --wait"
	c := exec.Command(args[0], append(args[1:], file)...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return fmt.Errorf("编辑器 %s 异常退出（%v），没有保存修改", args[0], err)
		}
		return fmt.Errorf("无法启动编辑器 %s：%w（可以用 EDITOR 环境变量指定）", args[0], err)
	}
	return nil
}

// writeInPlace replaces the file atomically, keeping its permissions.
func writeInPlace(path string, data []byte) error {
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
