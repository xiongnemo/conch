// Command conch is a proxy shell: it compiles a routing-table profile
// into kernel configuration and manages the kernel.
package main

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/xiongnemo/conch/internal/api"
	"github.com/xiongnemo/conch/internal/paths"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// errReported means the details were already printed for the user.
var errReported = errors.New("reported")

func main() {
	// Windows: cobra stops programs started from Explorer with this text.
	// The agent is started by Explorer at logon, so not it.
	cobra.MousetrapHelpText = "这是命令行程序，请在 PowerShell 或 Windows 终端里运行，例如 conch daemon。\n"
	if len(os.Args) > 1 && os.Args[1] == "agent" {
		cobra.MousetrapHelpText = ""
	}
	root := &cobra.Command{
		Use:           "conch",
		Short:         "路由表式分流 + 多跳链式代理",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newInitCmd(), newDaemonCmd(), newTUICmd(), newPairCmd(), newEditCmd(), newServiceCmd(), newAgentCmd(), newStatusCmd(), newRouteCmd(), newNodeCmd(), newChainCmd(), newSubCmd(), newImportCmd(), newCompileCmd(), newKernelCmd(), newPasswdCmd(), newSysProxyCmd(), newTUNCmd(), newDoctorCmd(), newEnvCmd(), newRunCmd(), &cobra.Command{
		Use:   "version",
		Short: "显示版本",
		Run:   func(cmd *cobra.Command, _ []string) { fmt.Fprintln(cmd.OutOrStdout(), version) },
	})
	localize(root)
	if cmd, err := root.ExecuteC(); err != nil {
		if !errors.Is(err, errReported) {
			msg, _ := cliError(err, cmd)
			fmt.Fprintln(os.Stderr, "错误：", msg)
			if hint := loginHint(err); hint != "" {
				fmt.Fprintln(os.Stderr, hint)
			}
		}
		os.Exit(1)
	}
}

// loginHint says where the daemon's password is when it refused ours.
func loginHint(err error) string {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
		return ""
	}
	s, _, _ := clientSettings()
	if rec, ok := readAPIRecord(); ok && rec.Env != "" && rec.Env != s.PasswordFile {
		return fmt.Sprintf("提示：daemon 用的是 %s 里的 CONCH_PASSWORD，这里读到的是 %s", rec.Env, cmp.Or(s.PasswordFile, "（没有找到密码）"))
	}
	return fmt.Sprintf("提示：密码是 .env 里的 CONCH_PASSWORD，先找当前目录，再找 %s；也可以用环境变量 CONCH_PASSWORD", paths.ConfigDir())
}
