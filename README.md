# Nautilus

路由表式分流 + 多跳链式代理的外壳。它把一份好读的 `profile.yaml` 编译成 mihomo 或 xray 的配置，替你托管内核进程，并提供 Web UI、TUI、浏览器扩展和命令行。

- **路由表，指哪打哪**：手动条目越具体越优先，与书写顺序无关；只有规则列表之间讲顺序。
- **链式代理是一等公民**：`AI-Exit: [香港自动, home]`，路由条目可以直接指向一条链，每一跳都能单独测速。
- **两个完整的内核**：mihomo 和 xray；trojan-go 节点由 trojan-go 边车运行。
- **一套 API，多个界面**：Web UI（带登录）、TUI、浏览器扩展、CLI 用的是同一个 API。
- 订阅、系统代理、TUN、系统服务、崩溃后自动恢复系统设置。

## 安装

从 Releases 下载对应系统的压缩包，或者 deb / rpm / apk / Arch 软件包。路由器（OpenWrt 等）用 `nautilus-lite`，它没有 TUI，内存占用更小。

内核不需要自己装：第一次运行 `nautilus daemon` 时会自动下载并校验（每个 nautilus 版本都内置了测试过的内核版本和 sha256）。也可以手动安装：

```sh
nautilus kernel install mihomo          # 或 xray --geodata、trojan-go
nautilus kernel install mihomo --mirror https://your-mirror/   # 通过镜像下载，同样会校验
```

## 快速开始

1. 参考 [examples/profile.yaml](examples/profile.yaml) 写一份 `profile.yaml`，放在当前目录或 `~/.config/nautilus/`。
2. 运行 `nautilus daemon`。第一次运行会生成登录密码，保存在 `.env` 里并打印出来。
3. 浏览器打开 <http://127.0.0.1:9277/>，或者在另一个终端运行 `nautilus tui`。
4. 让系统使用 nautilus：`nautilus sysproxy on`（daemon 退出时自动恢复原来的设置），或者开启 TUN：`nautilus tun on`。

改了 `profile.yaml` 不需要重启，daemon 会自动应用；配置有错时内核继续使用上一份可用的配置，错误显示在 Web UI 和 `nautilus status` 里。用 `nautilus edit` 修改，可以在保存前先检查。

## 路由表

```yaml
routes:
  default: 节点选择                 # 什么都没命中时走这里
  entries:                          # 手动条目：越具体越优先
    openai.com: AI-Exit             # 含所有子域名
    mail.google.com: DIRECT         # 比 google.com 具体，所以优先
    google.com: 节点选择
    =api.example.com: DIRECT        # 只匹配这个域名本身
    10.0.0.0/8: DIRECT              # 默认只匹配直接用 IP 访问的流量
    app:Telegram: 香港自动          # 按应用
  lists:                            # 规则列表：从上到下
    - { list: ads, via: REJECT }
    - { list: geosite:cn, via: DIRECT }
```

规则只有三条：手动条目永远先于规则列表；同类手动条目越具体越优先（应用 → 精确域名 → 子域名多的 → 关键词 → 前缀长的 IP）；规则列表之间从上到下。

看一个地址会怎么走、为什么：

```sh
nautilus route get chatgpt.com
nautilus route add openai.com AI-Exit --for 2h       # 临时条目，到期自动删除
nautilus route del openai.com
nautilus route list
```

在 Web UI、TUI 和浏览器扩展里也能做同样的事，还能从「连接」和「加载失败的网站」里一键给某个网站指定出口。

## 链式代理

```yaml
chains:
  AI-Exit: [香港自动, home]        # 先进香港自动，再从 home 出去
  经家里: [home, 香港自动]          # 出口组也可以放在后面的跳
```

第一跳可以是节点、出口组或另一条链；后面的跳可以是节点或只含节点的出口组。对链测速会给出每一跳的延迟，连不通时能看出断在哪一跳。也可以在界面里用分享链接添加节点、拼出新的链（`nautilus node add`、`nautilus chain add`），这些都写在 `managed.yaml`。

## 订阅

```yaml
subscriptions:
  - { name: 机场, url: https://example.com/sub, interval: 12h, import: [nodes, groups, rules] }
routes:
  lists:
    - { list: 机场 }                 # 机场自带的规则，保留原有顺序
```

支持 Clash 配置和分享链接两种订阅。机场规则作为一个规则列表导入，你自己的手动条目永远优先于它。下载失败或内容不对时继续使用缓存。

## 界面

- **Web UI**：daemon 自带，地址和密码见上文。密码在 `.env` 的 `NAUTILUS_PASSWORD` 里，`nautilus passwd` 可以修改；`NAUTILUS_AUTH=off` 关闭登录（只允许本机访问）。
- **TUI**：`nautilus tui`，按 `?` 查看按键。
- **浏览器扩展**：在 `extension/` 里运行 `npm ci && npm run build`，Chrome / Edge 加载 `dist/chrome`，Firefox 加载 `dist/firefox`。然后用 `nautilus pair` 或 Web UI 里的「配对浏览器扩展」拿到配对码，填进扩展弹窗。扩展只能查看和修改路由。

## 系统服务与 TUN

```sh
sudo nautilus service install      # systemd / launchd / Windows 服务，开机启动，可以开 TUN
nautilus service status
sudo nautilus service uninstall    # 保留配置和数据
```

服务会带上你现在的 profile、已下载的内核和登录密码。服务改不了每个用户的系统代理，所以每个用户登录后会运行 `nautilus agent` 来设置。

不装服务也能开 TUN：Linux 上给内核加权限（`sudo nautilus kernel setcap`，升级内核后要重做一次）；macOS 需要 root；Windows 需要管理员。macOS 上开启 TUN 时，nautilus 会临时把系统 DNS 指向一个能被 TUN 接管的地址，关闭时恢复。xray 内核暂不支持 TUN。

## 文件

| 文件 | 内容 |
| --- | --- |
| `profile.yaml` | 你写的配置，nautilus 只读不写 |
| `managed.yaml` | 在界面和命令行里添加的节点、链和条目 |
| `.env` | `NAUTILUS_PASSWORD`、`NAUTILUS_AUTH`、`NAUTILUS_LISTEN`、`NAUTILUS_TLS_CERT` / `NAUTILUS_TLS_KEY` |
| 数据目录 | 内核、缓存、`state.json`（选择的节点、开关、临时条目） |

`.env` 先读环境变量，再读当前目录，最后读 `~/.config/nautilus/.env`。

## 常用命令

| 命令 | 作用 |
| --- | --- |
| `nautilus daemon` | 运行内核和 Web UI |
| `nautilus tui` | 终端界面 |
| `nautilus status` | 查看状态 |
| `nautilus route get/add/del/list` | 查看和修改路由 |
| `nautilus node add/del`、`nautilus chain add/del` | 添加节点、拼链 |
| `nautilus sub update`、`nautilus import` | 更新订阅；把分享链接或 Clash 配置里的节点转换成 profile 的写法 |
| `nautilus compile` | 查看生成的内核配置 |
| `nautilus sysproxy on/off`、`nautilus tun on/off` | 系统代理、TUN |
| `nautilus run -- <命令>` | 只让一个程序走代理 |
| `nautilus doctor --fix` | 检查常见问题，恢复残留的系统代理和 DNS |
| `nautilus pair` | 配对浏览器扩展 |
| `nautilus edit` | 编辑 profile，保存前检查 |

## 开发

```sh
go test ./...
# 用真实内核跑端到端测试：
export NAUTILUS_MIHOMO=$(nautilus kernel path mihomo) NAUTILUS_XRAY=$(nautilus kernel path xray) \
       NAUTILUS_TROJAN_GO=$(nautilus kernel path trojan-go)
go test ./internal/e2e -count=1
```
