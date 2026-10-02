package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/xiongnemo/conch/internal/model"
	"github.com/xiongnemo/conch/internal/paths"
	"github.com/xiongnemo/conch/internal/subscription"
)

func newInitCmd() *cobra.Command {
	var output, name string
	var force bool
	cmd := &cobra.Command{
		Use:   "init [订阅地址]",
		Short: "生成一份能直接用的 profile.yaml，例如 conch init https://example.com/sub",
		Long: `生成一份能直接用的 profile.yaml，默认放在配置目录里。

给了订阅地址的话，会先下载一次订阅：订阅自带分组和规则（Clash 配置）就直接用机场的规则；
只有节点的话，就建一个“自动选择”和一个“节点选择”出口组，国内网站直连，其他走代理。
不给订阅地址，生成的 profile 让所有连接直连，里面有添加订阅和节点的写法。`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if output == "" {
				output = filepath.Join(paths.ConfigDir(), "profile.yaml")
			}
			if _, err := os.Stat(output); err == nil && !force {
				return fmt.Errorf("%s 已经存在；要重新生成就加上 --force（原来的文件会改名为 %s.bak）", output, filepath.Base(output))
			}
			var text, summary string
			if len(args) == 0 {
				text = directProfile
			} else {
				snap, err := firstDownload(cmd, name, args[0])
				if err != nil {
					return err
				}
				text, summary = starterProfile(name, args[0], snap), "，订阅里有 "+snap.Summary()
			}
			if err := writeProfile(output, text); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "已生成 %s%s。\n", output, summary)
			fmt.Fprintln(out, "接下来运行 conch daemon，然后在浏览器打开 http://127.0.0.1:9277/ ；之后用 conch edit 修改。")
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&output, "output", "o", "", "写到哪个文件（默认是配置目录里的 profile.yaml）")
	f.StringVar(&name, "name", "机场", "订阅的名字")
	f.BoolVar(&force, "force", false, "文件已经存在时覆盖它（原来的改名为 .bak）")
	return cmd
}

// firstDownload fetches the subscription into the cache the daemon reads,
// so its first start needs no download.
func firstDownload(cmd *cobra.Command, name, url string) (*subscription.Snapshot, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return nil, errors.New("订阅地址应该以 http:// 或 https:// 开头（单个节点的分享链接请用 conch import）")
	}
	s := &subscription.Store{Dir: paths.SubscriptionsDir(), Log: cmd.ErrOrStderr()}
	snap, _, err := s.Update(cmd.Context(), &model.Subscription{Name: name, URL: url})
	if err != nil {
		return nil, fmt.Errorf("%w\n订阅下载不下来的话，可以先运行 conch init 生成一份直连的 profile，再把订阅加进去", err)
	}
	for _, w := range snap.Warnings {
		fmt.Fprintln(cmd.ErrOrStderr(), "警告：", w)
	}
	return snap, nil
}

// starterProfile routes with the subscription's own rules when it has
// them; otherwise mainland sites go direct and the rest through a group of
// all nodes.
func starterProfile(name, url string, snap *subscription.Snapshot) string {
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) } // JSON strings are YAML
	var b strings.Builder
	b.WriteString(header)
	if len(snap.Rules) > 0 {
		fmt.Fprintf(&b, `subscriptions:
  - { name: %[1]s, url: %[2]s, interval: 12h, import: [nodes, groups, rules] }

routes:
  # 没写 default：用机场规则最后的 MATCH 指向的出口
  entries:                     # 手动条目：越具体越优先，永远先于规则列表
    # openai.com: 某个出口组或节点
  lists:                       # 规则列表：从上到下
    - { list: %[1]s }          # 机场自带的规则
`, q(name), q(url))
		return b.String()
	}
	fmt.Fprintf(&b, `subscriptions:
  - { name: %[1]s, url: %[2]s, interval: 12h }

groups:
  - { name: 自动选择, type: url-test, filter: "." }                  # 所有节点里延迟最低的
  - { name: 节点选择, type: select, members: [自动选择], filter: "." } # 在界面里手动选

routes:
  default: 节点选择
  entries:                     # 手动条目：越具体越优先，永远先于规则列表
    # openai.com: 某个出口组或节点
  lists:                       # 规则列表：从上到下
    - { list: geosite:cn, via: DIRECT }
    - { list: geoip:cn, via: DIRECT }
`, q(name), q(url))
	return b.String()
}

const header = `# conch 的配置，由 conch init 生成。保存以后，正在运行的 daemon 会自动应用。
# 完整的写法见 https://github.com/xiongnemo/conch/blob/main/examples/profile.yaml

`

const directProfile = header + `# 现在所有连接都直连。加上订阅或节点以后再分流，例如：
#
# subscriptions:
#   - { name: 机场, url: https://example.com/sub, interval: 12h, import: [nodes, groups, rules] }
# nodes:
#   - { name: home, type: socks5, server: 192.0.2.1, port: 1080 }
# routes:
#   default: home
#   lists:
#     - { list: 机场 }

routes:
  default: DIRECT
`

// writeProfile writes text to path, keeping what was there as .bak. Only
// the user can read it: a subscription URL is as good as a password.
func writeProfile(path, text string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		if err := os.Rename(path, path+".bak"); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(text), 0o600)
}
