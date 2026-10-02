// Command conch is a proxy shell: it compiles a routing-table profile
// into kernel configuration and manages the kernel.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
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
	root.AddCommand(newDaemonCmd(), newTUICmd(), newPairCmd(), newEditCmd(), newServiceCmd(), newAgentCmd(), newStatusCmd(), newRouteCmd(), newNodeCmd(), newChainCmd(), newSubCmd(), newImportCmd(), newCompileCmd(), newKernelCmd(), newPasswdCmd(), newSysProxyCmd(), newTUNCmd(), newDoctorCmd(), newEnvCmd(), newRunCmd(), &cobra.Command{
		Use:   "version",
		Short: "显示版本",
		Run:   func(cmd *cobra.Command, _ []string) { fmt.Fprintln(cmd.OutOrStdout(), version) },
	})
	if err := root.Execute(); err != nil {
		if !errors.Is(err, errReported) {
			fmt.Fprintln(os.Stderr, "错误：", err)
		}
		os.Exit(1)
	}
}
