# Conch

[![ci](https://github.com/xiongnemo/conch/actions/workflows/ci.yml/badge.svg)](https://github.com/xiongnemo/conch/actions/workflows/ci.yml)

路由表式分流 + 多跳链式代理的外壳。它把一份好读的 `profile.yaml` 编译成 mihomo、xray 或 sing-box 的配置，替你托管内核进程，并提供 Web UI、TUI、浏览器扩展和命令行。

- **路由表，指哪打哪**：手动条目越具体越优先，与书写顺序无关；只有规则列表之间讲顺序。
- **链式代理是一等公民**：`AI-Exit: [香港自动, home]`，路由条目可以直接指向一条链，每一跳都能单独测速。
- **三个内核**：mihomo、xray 和 sing-box（运行中随时切换：Web UI 页头的内核下拉框、TUI 概览页按 `K`，或 `conch kernel use xray`；系统代理、TUN 和模式保持不变，下次启动沿用），trojan-go 节点由 trojan-go 边车运行。
- **一套 API，多个界面**：Web UI（带登录）、TUI、浏览器扩展、CLI 用的是同一个 API。
- 订阅、系统代理、TUN、系统服务、崩溃后自动恢复系统设置。

## 安装

从 [Releases](https://github.com/xiongnemo/conch/releases) 下载对应系统的压缩包，或者 deb / rpm / apk / Arch 软件包。路由器（OpenWrt 等）用 `conch-lite`，它没有 TUI，内存占用更小。标着 Latest 的是正式版本（`v0.1.0` 这样补丁号为 0 的）；main 上每个通过 CI 的提交也会发布成预发布版本（Pre-release），版本号的规则见 [docs/versioning.md](docs/versioning.md)。

Linux 和 macOS 也可以从 [package.anzupop.com](https://package.anzupop.com) 用 apt / dnf / apk / MacPorts 安装，以后跟着系统一起更新（每种的用法见那个页面）。那里的 `stable` 是正式版本，`nightly` 是预发布版本；conch 现在还只有预发布版本，所以先用 `nightly`：

```sh
sudo curl -fsSLo /usr/share/keyrings/nemo.gpg https://package.anzupop.com/keys/nemo-packages.gpg
echo "deb [signed-by=/usr/share/keyrings/nemo.gpg] https://package.anzupop.com/apt nightly main" | sudo tee /etc/apt/sources.list.d/nemo-nightly.list
sudo apt update && sudo apt install conch
```

Windows 可以用 Scoop：

```powershell
scoop bucket add nemo https://github.com/xiongnemo/windows-binaries-scoop-bucket
scoop install nemo/conch-nightly   # 预发布版本
```

内核不需要自己装：第一次运行 `conch daemon` 时会自动下载并校验（每个 conch 版本都内置了验证过的内核版本和 sha256）。「验证过」是指 conch 的 CI 用这个版本的真实内核跑过全部测试；内核遇到不认识的配置往往悄悄忽略，所以用了没验证过的版本（例如 `--version` 指定的旧版本，或升级 conch 之前装的内核），`conch status`、`conch doctor`、Web UI 和 TUI 都会标出来，换成验证过的版本只要运行 `conch kernel install <内核>` 再重启 daemon。连不上 GitHub 的话，把环境变量 `CONCH_MIRROR` 设成下载镜像，例如 `CONCH_MIRROR=https://ghfast.top conch daemon`；自动下载和 `conch kernel` 命令都会用它，从镜像下载的文件同样会校验。也可以手动安装：

```sh
conch kernel install mihomo          # 或 xray --geodata、sing-box、trojan-go
conch kernel install mihomo --mirror https://your-mirror/   # 只这一次用镜像
```

下载的文件可以用 `checksums.txt` 校验；`checksums.txt` 带有发布时由 GitHub Actions 生成的 Sigstore 签名：

```sh
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/xiongnemo/conch/\.github/workflows/release\.yml@refs/(tags/v|heads/main$)' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

## 快速开始

1. 运行 `conch init <订阅地址>`，生成一份能直接用的 `~/.config/conch/profile.yaml`：订阅自带规则就用机场的规则，只有节点的话国内网站直连、其他走代理。也可以参考 [examples/profile.yaml](examples/profile.yaml) 自己写一份，放在当前目录或 `~/.config/conch/`。
2. 运行 `conch daemon`。第一次运行会生成登录密码，保存在 `~/.config/conch/.env` 里并打印出来。
3. 浏览器打开 <http://127.0.0.1:9277/>，或者在另一个终端运行 `conch tui`。
4. conch 启动后只是一个 HTTP + SOCKS5 代理（默认端口 7890），不会自己改系统代理，也不会开 TUN。要让整个系统都走它：`conch sysproxy on`（daemon 退出时自动恢复原来的设置），或者开启 TUN：`conch tun on`。这两个开关和模式开关（规则 / 全局 / 直连）都只管这一次运行；想每次启动都这样，就写进 profile：`inbound: { system-proxy: true }`、`tun: { enable: true }`、`mode: global`。

改了 `profile.yaml` 不需要重启，daemon 会自动应用；配置有错时内核继续使用上一份可用的配置，错误显示在 Web UI 和 `conch status` 里。用 `conch edit` 修改，可以在保存前先检查。

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
conch route get chatgpt.com
conch route add openai.com via AI-Exit --for 2h   # 临时条目，到期自动删除；--for run 表示到 conch 停止为止（via 可以省略）
conch route del openai.com
conch route list
```

在 Web UI、TUI 和浏览器扩展里也能做同样的事，还能从「连接」和「加载失败的网站」里一键给某个网站指定出口。

## 链式代理

```yaml
chains:
  AI-Exit: [香港自动, home]        # 先进香港自动，再从 home 出去
  经家里: [home, 香港自动]          # 出口组也可以放在后面的跳
```

第一跳可以是节点、出口组或另一条链；后面的跳可以是节点或只含节点的出口组。对链测速会给出每一跳的延迟，连不通时能看出断在哪一跳。也可以在界面里添加节点、新建出口组、拼出新的链（`conch node add`、`conch group add`、`conch chain add`），这些都写在 `managed.yaml`。Web UI 和 TUI 里添加节点有三种写法：粘贴分享链接（一次可以粘贴多条，一行一条）；按协议填表，只显示这个协议要填的项；或者直接写 profile 的写法。填写时，正在运行的内核会先检查一遍，有错误或警告当场显示。用 conch 添加的节点之后还能在同一个表单里修改。

## 订阅

```yaml
subscriptions:
  - { name: 机场, url: https://example.com/sub, interval: 12h, import: [nodes, groups, rules] }
routes:
  lists:
    - { list: 机场 }                 # 机场自带的规则，保留原有顺序
```

支持 Clash 配置、分享链接、sing-box 配置（JSON）和 SIP008 四种订阅；sing-box 配置里的节点和出口组会转成 profile 的写法，路由规则不导入。机场规则作为一个规则列表导入，你自己的手动条目永远优先于它。下载失败或内容不对时继续使用缓存。

订阅先直接下载（不少机场不接受经由自家节点更新订阅），失败了再经由正在运行的内核下载；规则列表也是这样，每天更新一次。还没下载成功的订阅，只要 profile 不依赖它，conch 会先不带它运行，之后自动重试。机场给节点改了名字时，出口组里选中的节点会跟着改过去。

## 界面

- **Web UI**：daemon 自带，地址和密码见上文。密码在 `.env` 的 `CONCH_PASSWORD` 里，`conch passwd` 可以修改；`CONCH_AUTH=off` 关闭登录（只允许本机访问）。
- **TUI**：`conch tui`，按 `?` 查看按键。
- **浏览器扩展**：还没有上架商店。从 Releases 下载 `conch-extension-chrome-*.zip` 并解压（或者在 `extension/` 里运行 `npm ci && npm run build`，得到 `dist/chrome`），在 Chrome / Edge 的扩展页面打开开发者模式，选「加载已解压的扩展程序」。Firefox 在 `about:debugging` 里临时载入 `conch-extension-firefox-*.zip`，重启后要重新载入。然后用 `conch pair` 或 Web UI 里的「配对浏览器扩展」拿到配对码，填进扩展弹窗。扩展只能查看和修改路由。

## 登录时自动启动、系统服务与 TUN

只是想开机后不用手动运行 conch daemon，用自动启动就够了，不需要 sudo 或管理员权限：

```sh
conch autostart on       # 登录后自动运行 conch daemon，现在也启动
conch autostart status
conch autostart off
```

它就是以你自己的身份运行 `conch daemon`：用你的 profile（开启时记下的那一份）、内核和密码，启动时只是 HTTP + SOCKS5 代理。Linux 用 systemd 用户服务（日志：`journalctl --user -u conch`；没有 systemd 用户会话时改用桌面的自启动项），macOS 用 LaunchAgent（日志在 `~/.local/state/conch/daemon.log`），Windows 用注册表的 Run 项（不弹窗口，日志在 `%USERPROFILE%\.local\state\conch\daemon.log`）。

要在还没登录时就运行，或者要用 TUN，装成系统服务（和自动启动二选一）：

```sh
sudo conch service install      # systemd / launchd / Windows 服务，开机启动，可以开 TUN
conch service status
sudo conch service uninstall    # 保留配置和数据
```

服务会带上你现在的 profile、已下载的内核和登录密码。服务改不了每个用户的系统代理，所以每个用户登录后会运行 `conch agent` 来设置。

不装服务也能开 TUN：Linux 上给内核加权限（`sudo conch kernel setcap`，升级内核后要重做一次）；macOS 需要 root；Windows 需要管理员。macOS 上开启 TUN 时，conch 会临时把系统 DNS 指向一个能被 TUN 接管的地址，关闭时恢复（sing-box 自己处理）。xray 内核的 TUN：Linux 上 xray 只建网卡，系统路由由 conch 来配（发往局域网路由器的 DNS 也能接管），所以 conch 自己也要有权限（root 或系统服务）；macOS 和 Windows 上由 xray 自己配路由，Windows 上 xray 需要和 xray.exe 放在一起的 wintun.dll，`conch kernel install xray` 会一起装好。

## 文件

conch 在 Linux、macOS 和 Windows 上都按 [XDG Base Directory](https://specifications.freedesktop.org/basedir-spec/latest/) 放自己的文件（Windows 上 `~` 是 `%USERPROFILE%`）：

| 类别 | 目录 | 里面有什么 |
| --- | --- | --- |
| 配置 | `~/.config/conch` | `profile.yaml`（你写的配置，conch 只读不写）、`managed.yaml`（在界面和命令行里添加的节点、链和条目）、`.env`（`CONCH_PASSWORD`、`CONCH_AUTH`、`CONCH_LISTEN`、`CONCH_TLS_CERT` / `CONCH_TLS_KEY`） |
| 数据 | `~/.local/share/conch` | `pairings.json`（配对过的浏览器扩展） |
| 状态 | `~/.local/state/conch` | `state.json`（选择的节点、开关、临时条目、崩溃后要恢复的系统设置）、`api.json`（daemon 在哪里监听、密码在哪个 `.env`）、`agent.json`、`daemon.log`（macOS 和 Windows 上登录时自动启动的 daemon 的日志）、`agent.log` |
| 缓存 | `~/.cache/conch` | `kernels`（下载的内核）、`home`（内核的工作目录，有 geodata）、`lists`（规则列表）、`subscriptions`（订阅）、`certs.json`（见下） |

内核的 socket 和 pid 文件放在 `$XDG_RUNTIME_DIR/conch`，没有这个变量时放在 `~/.local/state/conch/run`。

环境变量：

- `XDG_CONFIG_HOME`、`XDG_DATA_HOME`、`XDG_STATE_HOME`、`XDG_CACHE_HOME`、`XDG_RUNTIME_DIR`：设置了就用 `$XDG_…/conch` 代替上面的目录，每个系统上都一样；只认绝对路径，相对路径会被忽略。
- `CONCH_CONFIG_DIR`：配置目录，优先于上面这些。
- `CONCH_DATA_DIR`：数据、状态、缓存和 socket 都放在这一个目录里（系统服务就是这样用的），也优先于上面这些。

`.env` 每一项按这个顺序找：环境变量、当前目录的 `.env`、`~/.config/conch/.env`。当前目录的 `.env` 适合把 profile 和密码一起放在单独的目录里（登录时自动启动会切换到 profile 所在的目录）；第一次运行生成的密码写在 `~/.config/conch/.env`。

旧版本把文件放在别处：Windows 的 `%APPDATA%\conch`（配置）和 `%LOCALAPPDATA%\conch`（其他），macOS 的 `~/Library/Application Support/conch` 和 `~/Library/Logs/conch`，Linux 的 `~/.local/share/conch`（全部），生成的密码写在运行 `conch daemon` 的目录的 `.env` 里。这些文件不迁移也照样能用：每个文件单独找，新位置有就用新位置，没有就用旧位置，并在 stderr 提醒一次。

`conch migrate` 把它们移到新的位置，先用 `conch migrate --dry-run` 看看要做什么：

- 从不覆盖：两边都有的文件，内容相同就删掉旧的，不同就两份都保留，报告冲突并以非 0 退出；旧目录空了就删掉。
- `api.json`、`.env` 和登录时自动启动（systemd 用户服务、LaunchAgent、注册表 Run 项）里指向旧位置的路径会改成新的；profile 里提到旧位置的地方会列出来，需要自己改。
- 当前目录里旧版本生成的 `.env` 会移到 `~/.config/conch`；在别的目录运行过 `conch daemon` 的话用 `--from <目录>`。
- daemon 在运行时不迁移，先停掉它；`conch agent` 和 `conch tui` 检测不到，也请先退出。

系统服务（`sudo conch service install`）的文件不在这里，迁移也不碰它们：Linux 是 `/etc/conch` 和 `/var/lib/conch`，macOS 是 `/Library/Application Support/conch`，Windows 是 `C:\ProgramData\conch`。

节点用 mihomo 的写法；每一项设置在 mihomo、xray、sing-box 和 trojan-go 边车里怎么翻译、哪些内核做不到，见 [docs/node-translation.md](docs/node-translation.md)。

节点上的证书指纹（`fingerprint`，分享链接里的 `pinSHA256`）是证书的 SHA256。mihomo 和 xray 直接按它校验；sing-box 和 trojan-go 不支持这种写法，conch 会先连一次服务器取到证书，确认和指纹一致后，换算成它们能用的写法（证书公钥的 SHA256，或只信任这一张证书），记在 `certs.json` 里。还没取到时按常规校验证书，不会因此跳过校验；节点写了指纹时，`skip-cert-verify` 不起作用。

## 常用命令

| 命令 | 作用 |
| --- | --- |
| `conch init` | 从订阅地址生成 profile.yaml |
| `conch daemon` | 运行内核和 Web UI |
| `conch tui` | 终端界面 |
| `conch status` | 查看状态 |
| `conch route get/add/del/list` | 查看和修改路由 |
| `conch node add/del`、`conch group add/del`、`conch chain add/del` | 添加节点、出口组，拼链 |
| `conch sub update`、`conch import` | 更新订阅；把分享链接或 Clash 配置里的节点转换成 profile 的写法 |
| `conch compile` | 查看生成的内核配置 |
| `conch sysproxy on/off`、`conch tun on/off` | 系统代理、TUN |
| `conch run -- <命令>` | 只让一个程序走代理 |
| `conch doctor --fix` | 检查常见问题，恢复残留的系统代理和 DNS |
| `conch pair` | 配对浏览器扩展 |
| `conch edit` | 编辑 profile，保存前检查 |
| `conch kernel use [内核]` | 切换内核；不写内核名则列出可用的内核 |
| `conch autostart on/off` | 登录时自动运行 daemon（不需要管理员权限） |
| `conch migrate` | 把旧版本放在旧位置的文件移到新的位置（见「文件」） |

## 开发

```sh
go test ./...
# 用真实内核跑端到端测试：
export CONCH_MIHOMO=$(conch kernel path mihomo) CONCH_XRAY=$(conch kernel path xray) \
       CONCH_SING_BOX=$(conch kernel path sing-box) CONCH_TROJAN_GO=$(conch kernel path trojan-go)
go test ./internal/e2e -count=1
```

每次推送，CI 会在 Linux、macOS 和 Windows 上跑单元测试，在 Linux 上用真实内核和 Chrome 跑端到端测试，并把这次提交的各平台二进制和浏览器扩展放在 Actions 运行页面的 Artifacts 里，方便试用。
