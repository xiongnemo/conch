package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

// Chinese for what cobra and pflag would otherwise say in English: the
// help layout, the help flag and command, shell completion, and the
// errors for wrong arguments.

const usageTemplate = `用法：{{if .Runnable}}
  {{useLine .}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [命令]{{end}}{{if gt (len .Aliases) 0}}

别名：
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

例子：
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

命令：{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

选项：
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

通用选项：
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableSubCommands}}

运行 "{{.CommandPath}} [命令] --help" 查看命令的用法。{{end}}
`

// localize sets up the Chinese help for root and every command under it.
// Call it once all commands are added.
func localize(root *cobra.Command) {
	cobra.AddTemplateFunc("useLine", func(c *cobra.Command) string {
		return strings.Replace(c.UseLine(), "[flags]", "[选项]", 1)
	})
	root.SetUsageTemplate(usageTemplate)
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	for _, c := range root.Commands() {
		switch c.Name() {
		case "help":
			c.Use, c.Short, c.Long = "help [命令]", "显示命令的帮助", "显示任何一个命令的帮助，例如 conch help route。"
		case "completion":
			c.Short = "生成 shell 的自动补全脚本"
			c.Long = "生成 bash、zsh、fish 或 PowerShell 的自动补全脚本，例如在 bash 里运行 source <(conch completion bash)。"
			for _, sh := range c.Commands() {
				sh.Short = "生成 " + sh.Name() + " 的自动补全脚本"
				sh.Long = completionHelp[sh.Name()]
				if f := sh.Flags().Lookup("no-descriptions"); f != nil {
					f.Usage = "补全时不显示说明"
				}
			}
		}
	}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Flags().Lookup("help") == nil {
			c.Flags().BoolP("help", "h", false, "显示帮助")
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
}

var completionHelp = map[string]string{
	"bash": `在当前的 shell 里加载：
  source <(conch completion bash)

以后每次都加载：
  Linux：conch completion bash > /etc/bash_completion.d/conch
  macOS：conch completion bash > $(brew --prefix)/etc/bash_completion.d/conch

需要先装好 bash-completion。`,
	"zsh": `在当前的 shell 里加载：
  source <(conch completion zsh)

以后每次都加载：
  conch completion zsh > "${fpath[1]}/_conch"

如果还没有开启 zsh 的补全，先在 ~/.zshrc 里加上 autoload -U compinit; compinit。`,
	"fish": `在当前的 shell 里加载：
  conch completion fish | source

以后每次都加载：
  conch completion fish > ~/.config/fish/completions/conch.fish`,
	"powershell": `在当前的 PowerShell 里加载：
  conch completion powershell | Out-String | Invoke-Expression

以后每次都加载：把上面这行加进 PowerShell 的 profile。`,
}

// cliErrors are cobra's and pflag's errors about how a command was typed.
var cliErrors = []struct {
	re     *regexp.Regexp
	format string
}{
	{regexp.MustCompile(`^accepts (\d+) arg\(s\), received (\d+)$`), "需要 %s 个参数，给了 %s 个"},
	{regexp.MustCompile(`^accepts at most (\d+) arg\(s\), received (\d+)$`), "最多 %s 个参数，给了 %s 个"},
	{regexp.MustCompile(`^requires at least (\d+) arg\(s\), only received (\d+)$`), "至少需要 %s 个参数，只给了 %s 个"},
	{regexp.MustCompile(`^accepts between (\d+) and (\d+) arg\(s\), received (\d+)$`), "需要 %s 到 %s 个参数，给了 %s 个"},
	{regexp.MustCompile(`^unknown flag: (.+)$`), "没有 %s 这个选项"},
	{regexp.MustCompile(`^unknown shorthand flag: '(.)' in .+$`), "没有 -%s 这个选项"},
	{regexp.MustCompile(`^flag needs an argument: '(.)' in .+$`), "-%s 后面要写上值"},
	{regexp.MustCompile(`^flag needs an argument: (.+)$`), "%s 后面要写上值"},
	{regexp.MustCompile(`^invalid argument "(.*)" for "(.+)" flag: .+$`), "%[2]s 的值 %[1]q 不对"},
	{regexp.MustCompile(`^required flag\(s\) (.+) not set$`), "缺少选项 %s"},
}

var unknownCommand = regexp.MustCompile(`^unknown command "(.*)" for "(.*)"(?s:\n\nDid you mean this\?\n(.*))?$`)

// cliError says in Chinese what was wrong with how a command was typed,
// with where to look up the right way. It reports false for other errors.
func cliError(err error, cmd *cobra.Command) (string, bool) {
	msg := err.Error()
	if m := unknownCommand.FindStringSubmatch(msg); m != nil {
		s := fmt.Sprintf("没有 %s %s 这个命令", m[2], m[1])
		if sug := strings.Fields(m[3]); len(sug) > 0 {
			s += "，是不是想用 " + strings.Join(sug, "、") + "？"
		}
		return s + fmt.Sprintf("\n运行 %s --help 查看所有命令", m[2]), true
	}
	for _, e := range cliErrors {
		if m := e.re.FindStringSubmatch(msg); m != nil {
			args := make([]any, len(m)-1)
			for i, s := range m[1:] {
				args[i] = s
			}
			return fmt.Sprintf(e.format, args...) + fmt.Sprintf("\n运行 %s --help 查看用法", cmd.CommandPath()), true
		}
	}
	return msg, false
}
