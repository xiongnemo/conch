# Windows 手动测试脚本

在一台真实的 Windows 10（1803 以上）或 Windows 11 上，把 conch 从头到尾走一遍。每一步写了要做什么、应该看到什么；和预期不一样的地方，按最后一节的方法记下来。全部做完大约两小时，第 12、13 节需要管理员权限。

CI 已经在 Windows 上用真实的 mihomo、xray、sing-box、trojan-go 跑过端到端测试（分流、链、出口组、API、边车），在 Linux 上测过 TUN 和系统服务。所以这份脚本主要测 CI 测不了的部分：

- 系统代理和崩溃恢复；
- Windows 上的 TUN、服务和 agent；
- Web UI、TUI、浏览器扩展；
- 你自己的真实节点和订阅。

约定：

- 命令都在 **PowerShell** 里运行。要用 `curl.exe`，不要用 `curl`（PowerShell 5 里 `curl` 是 `Invoke-WebRequest` 的别名）。
- 「窗口 A」专门运行 daemon，「窗口 B」运行其他命令。两个窗口都先执行 0.3 节的命令。
- 节点和订阅用你自己的测试链接。**不要把链接、订阅地址和密码贴到 issue、截图或聊天里。**
- 下文的代理端口是 7890。如果 Clash、v2rayN 之类的软件占用了它，先退出那些软件，或者把 profile 和命令里的 7890 都换成别的端口（例如 17890）。

## 0. 准备

**0.1 下载**

打开 <https://github.com/xiongnemo/conch/actions/workflows/ci.yml>，点开最新一次成功（绿色）的运行，在页面底部的 Artifacts 里下载：

- `conch_windows_amd64.exe`（ARM 电脑下载 `conch_windows_arm64.exe`）
- `conch-extension`

新建文件夹 `C:\conch-test`，把 exe 放进去并改名为 `conch.exe`。把扩展的 zip 解压到 `C:\conch-test\extension`，里面应该有 `chrome` 和 `firefox` 两个文件夹。

**0.2 准备测试数据**

用记事本在 `C:\conch-test\links.txt` 里放好 5 个节点的分享链接（每行一个），按这个顺序：

| 代号 | 节点 |
| --- | --- |
| A | VLESS + REALITY |
| B | VMess + WebSocket + TLS |
| C | VMess + gRPC + TLS |
| D | VLESS + WebSocket + TLS（带 `?ed=2048`） |
| E | Hysteria2 |

再准备好订阅地址。

**0.3 打开窗口**

```powershell
cd C:\conch-test
$env:Path = "C:\conch-test;" + $env:Path
conch version
```

预期：打印 `dev-` 加 7 位提交号。如果 SmartScreen 拦截，点「更多信息」→「仍要运行」。

**0.4 设置登录密码**

先把密码放进配置目录。这样不管在哪个目录运行命令，用的都是同一个密码，第 13 节的服务也会沿用它。

```powershell
mkdir $env:APPDATA\conch -Force | Out-Null
Set-Content -Encoding utf8 $env:APPDATA\conch\.env "CONCH_PASSWORD=换成你自己的测试密码"
```

**0.5 记录环境，备份系统代理设置**

```powershell
[Environment]::OSVersion.Version; $env:PROCESSOR_ARCHITECTURE
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' |
  Select-Object ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL | Format-List |
  Tee-Object C:\conch-test\proxy-before.txt
```

最后对照 `proxy-before.txt` 确认系统代理恢复了原样。

- [ ] 0 准备完成

## 1. 双击运行

在资源管理器里双击 `conch.exe`。

预期：弹出黑色窗口，显示「这是命令行程序，请在 PowerShell 或 Windows 终端里运行，例如 conch daemon。」，几秒后自动关闭。

- [ ] 1 通过

## 2. 安装内核

```powershell
conch kernel install mihomo
conch kernel install xray --geodata
conch kernel install sing-box
conch kernel path mihomo
conch kernel path sing-box
```

预期：每个内核都下载、校验 sha256，然后装到 `%LOCALAPPDATA%\conch\kernels\` 下；`kernel path` 打印 exe 的完整路径。

- [ ] 2 通过

## 3. 测试用的 profile

**3.1 转换分享链接**

```powershell
conch import links.txt
```

预期：输出 `nodes:` 和 5 行节点，逐行检查：

- A 有 `flow: xtls-rprx-vision`、`reality-opts: {public-key: …}`、`client-fingerprint`；
- B 有 `network: ws` 和 `ws-opts`；
- C 有 `network: grpc` 和 `grpc-opts: {grpc-service-name: …}`；
- D 的 `ws-opts` 里 `path: /`，并带有 `max-early-data: 2048`；
- E 有 `fingerprint`（证书指纹）。

**3.2 写 profile**

运行 `notepad $env:APPDATA\conch\profile.yaml`，填入下面的内容：

- 把上一步输出的 5 行节点粘贴到 `nodes:` 下面；
- 把每行的 `name:` 依次改成 A、B、C、D、E；
- 填好订阅地址。

```yaml
subscriptions:
  - { name: 订阅, url: "这里填订阅地址", interval: 12h, import: [nodes, groups, rules] }

nodes:
  # 粘贴 5 行节点，name 依次改成 A B C D E

groups:
  - { name: 自建自动, type: url-test, members: [A, B, C, D, E] }
  - { name: 自建备用, type: fallback, members: [E, A, C] }
  - { name: 出口, type: select, members: [自建自动, 自建备用, A, B, C, D, E, 中转链, 组链, UDP链, DIRECT] }

chains:
  中转链: [D, A]        # 先进 D，从 A 出去
  组链: [自建自动, C]    # 出口组作为第一跳
  UDP链: [A, E]         # hysteria2（UDP）作为第二跳

routes:
  default: 出口
  entries:
    api.ipify.org: A
    ifconfig.me: C
    icanhazip.com: E
    ipinfo.io: 中转链
    ip.sb: 组链
    httpbin.org: B
    checkip.amazonaws.com: UDP链
    cloudflare.com: DIRECT
  lists:
    - { list: 订阅 }

inbound: { mixed-port: 7890 }
```

**3.3 三个内核都编译一遍**

```powershell
conch compile --backend mihomo > $null
conch compile --backend xray > $null
conch compile --backend sing-box > $null
```

预期：

- mihomo 没有错误；
- xray 和 sing-box 没有「错误」，只有几条「警告」，比如：订阅的出口组用了不同的测速地址；sing-box 无法使用 hysteria2 的证书指纹；sing-box 没有故障转移组和负载均衡组。

把警告抄下来。

- [ ] 3 通过

## 4. 启动 daemon（mihomo）

**4.1 首次运行生成密码（可选）**

```powershell
mkdir C:\conch-test\first-run | Out-Null; cd C:\conch-test\first-run
$env:CONCH_CONFIG_DIR = "C:\conch-test\first-run"; conch daemon
```

预期：打印「已生成登录密码，保存在 …\first-run\.env」；因为这里没有 profile，接着报错退出。然后清理：

```powershell
cd C:\conch-test; Remove-Item Env:CONCH_CONFIG_DIR; Remove-Item -Recurse first-run
```

**4.2 在窗口 A 启动**

```powershell
conch daemon --backend mihomo
```

预期：

- 下载订阅和规则列表；
- 打印 `Web UI：http://127.0.0.1:9277/`；
- 不应该弹出 Windows 防火墙的提示，因为 daemon 和内核都只监听 127.0.0.1。如果弹了，截图记下是哪个程序。

**4.3 在窗口 B 查看**

```powershell
conch status
conch sub list
conch doctor
```

预期：

- `status` 显示「内核：mihomo（运行中）」；
- `sub list` 显示「订阅：N 个节点，M 个出口组，K 条规则」，还有流量和到期日期；
- `doctor` 的每一项都是 ✓。

- [ ] 4 通过

## 5. 分流：指哪打哪

**5.1 逐个网站检查出口 IP**

在窗口 B 运行下面的脚本，第 7、11 节还会再用它：

```powershell
function Test-Routes($p = "http://127.0.0.1:7890") {
  $tests = [ordered]@{
    "https://api.ipify.org" = "A"; "https://ifconfig.me/ip" = "C"; "https://icanhazip.com" = "E"
    "https://ipinfo.io/ip" = "中转链(从 A 出)"; "https://api.ip.sb/ip" = "组链(从 C 出)"; "https://httpbin.org/ip" = "B"
    "https://checkip.amazonaws.com" = "UDP链(从 E 出)"; "https://www.cloudflare.com/cdn-cgi/trace" = "DIRECT(本机)"
  }
  foreach ($u in $tests.Keys) {
    $out = curl.exe -s -m 20 -x $p $u
    "{0,-42} {1,-16} {2}" -f $u, $tests[$u], [regex]::Match("$out", '(\d{1,3}\.){3}\d{1,3}').Value
  }
  curl.exe -s -m 20 -x $p -o NUL -w "google.com: %{http_code}`n" https://www.google.com/generate_204
  "SOCKS5: " + (curl.exe -s -m 20 --socks5-hostname 127.0.0.1:7890 https://api.ipify.org)
}
Test-Routes
```

预期：

- 写着 A、E、UDP链 的几行，出口是 A、E 服务器的 IP；
- C 和组链的出口是 C 服务器的 IP；
- DIRECT 是你本机的公网 IP；
- google.com 返回 204，SOCKS5 也能打印出 IP。

已知情况：如果 D 部署在 Cloudflare 上（Workers 一类），它连不上 Cloudflare 托管的网站，例如 ifconfig.co、example.com。这是服务器的限制，不是 conch 的问题。

**5.2 解释**

```powershell
conch route get api.ipify.org
conch route get "https://www.youtube.com/watch?v=1"
conch route get www.baidu.com
conch route list
```

预期：

- 显示「命中：…」和「出口：…」，例如「手动条目 api.ipify.org（profile.yaml:N）」「订阅 订阅 的规则 关键词 youtube」；
- 被压过的同一条规则只列一次；
- 订阅里按应用的规则合成一行（「订阅 订阅 的 N 条按应用的规则（… 等）」）。

**5.3 改路由**

依次运行，每条命令后按注释检查：

```powershell
conch route add example.net E --for 10m      # 已添加
conch route add httpbingo.org UDP链           # 永久条目，写进 managed.yaml
conch route add ifconfig.me A --for 5m        # 临时覆盖 profile 里的条目
conch route list                              # 看到「（临时，到 HH:MM）」和这几条
conch route get ifconfig.me                   # 命中：手动条目 ifconfig.me（临时条目，到 HH:MM）→ A
curl.exe -s -x http://127.0.0.1:7890 https://ifconfig.me/ip; ""   # 现在是 A 的 IP
conch route del ifconfig.me
conch route del example.net
conch route del httpbingo.org
conch route del api.ipify.org                 # 预期报错：条目写在 profile.yaml，conch 不会改动你手写的文件
```

- [ ] 5 通过

## 6. 改 profile 时的行为

**6.1 自动应用**

用记事本在 profile 的 `entries:` 下加一行 `    neverssl.com: C`，保存。约 3 秒后运行 `conch route get neverssl.com`，应该显示 → C。

**6.2 写错时**

把那一行改成 `    neverssl.com: 不存在`，保存。运行 `conch status`，预期：

- 显示「配置有问题（内核继续使用上一份可用的配置）」，并给出行号；
- `Test-Routes` 的结果和原来一样。

改回去之后，`status` 里不再有错误。

**6.3 内核崩溃**

在任务管理器里结束 `mihomo.exe`（窗口 A 里的 conch 不要结束）。几秒后运行 `conch status`，预期：

- 内核又是运行中，并显示「重启过 1 次」；
- `Test-Routes` 正常。

内核重启后一两秒内的请求失败，属于正常。

**6.4 conch edit**

运行 `conch edit`，会用记事本打开 profile：

1. 把某个出口名改错，保存并关闭记事本。预期：记事本重新打开，顶部用 `#>` 开头的几行列出错误。
2. 改对，保存并关闭。预期：命令打印「已保存 …；正在运行的 daemon 会自动应用」，文件里没有残留那几行 `#>`。

- [ ] 6 通过

## 7. Web UI

用浏览器打开 <http://127.0.0.1:9277/>。

**7.1 登录**

先输入一个错的密码，预期显示「密码不对」；再输入 0.4 设的密码。

**7.2 概览**

- 顶部显示「mihomo · 运行中」；
- 订阅一行写着：订阅：N 个节点…、已用 … / …、到期 2099-12-31 这种格式的日期、更新于 2026-10-02 12:34 这种格式的时间；
- 点「更新」，按钮变成「更新中…」，完成后时间刷新；
- 实时流量随浏览而变化。

**7.3 出口**

1. 每个出口组的成员都能点「测速」，显示 `xxx ms` 或「失败」。点「测速」**不会**改变选中的成员。
2. 在「出口」组里点 C，然后运行 `curl.exe -s -x http://127.0.0.1:7890 https://myip.wtf/text`，应该是 C 的 IP。再点回「自建自动」。
3. 链：点每条链的测速，每一跳都显示延迟（例如「D 210 ms → A 1100 ms」）。
4. 节点：在「粘贴分享链接添加节点」里粘贴 links.txt 的任意一行，点添加，节点列表里多出一个带「×」的节点；点「×」删除它。
5. 新建链：选第一跳和第二跳，起个名字，保存；它会出现在链的列表里，有「×」可以删除。

**7.4 路由**

1. 在「这个地址怎么走？」里输入 `https://www.youtube.com/`，显示命中的规则和出口。
2. 添加条目：目标 example.net，出口 E，有效期 1 小时。表格里出现「临时，到 HH:MM」，点「删除」去掉它。

**7.5 连接**

- 浏览几个网站时，连接列表显示每条连接的「命中」（哪条条目或订阅规则）和出口路径；点「断开」能断开一条连接。
- 运行 `curl.exe -s -m 10 -x http://127.0.0.1:7890 http://127.0.0.1:1/`（直连一个没有程序监听的端口）。「加载失败的网站」里会出现 127.0.0.1:1，经由 DIRECT，原因是连接被拒绝（Windows 上的原文类似「actively refused」）。点「分流…」可以给它指定出口。

**7.6 日志**

有内核的日志。

**7.7 模式**

- 点「全局」：所有流量走 GLOBAL 组，默认就是 profile 里的默认出口「出口」，所以 `Test-Routes` 里 DIRECT 那一行也变成代理的 IP；
- 点「直连」：所有行都是本机 IP；
- 最后点回「分流」。

- [ ] 7 通过

## 8. TUI

在 **Windows 终端**里运行 `conch tui`，再在旧的 PowerShell 窗口（conhost）里运行一次。

检查这些：

- 中文和 emoji（订阅的 🚀 ♻️ 等）对齐，没有乱码；
- 1–5 切换页面；
- 出口页：`t` 测速，`Enter` 展开出口组和选择成员；
- 路由页：`/` 输入地址查询；
- 连接页：`r` 给选中的网站指定出口，`x` 断开；
- `?` 显示帮助，`q` 退出。

注意：按了 `Esc` 之后马上按数字键，终端会把两次按键当成 Alt+数字，这不算问题。

- [ ] 8 通过

## 9. 其他命令

```powershell
conch node add (Get-Content links.txt -TotalCount 1)    # 打印「已添加节点 <名字>」，记下名字
conch chain add 测试链 C <上一步的名字>
conch route add example.org 测试链 --for 5m
curl.exe -s -x http://127.0.0.1:7890 -o NUL -w "%{http_code}`n" https://example.org/   # 200
conch node del <名字>       # 预期失败：它还在 测试链 里
conch route del example.org; conch chain del 测试链; conch node del <名字>
conch sub update            # 打印「更新订阅 订阅（通过 daemon）」和新的更新时间
conch run -- curl.exe -s https://api.ipify.org; ""     # 只有这一条命令走代理：默认出口的 IP
conch env --shell powershell                            # 打印 $env:HTTP_PROXY=… 等几行
conch pair                                              # 6 位配对码，2 分钟内有效
```

改密码（Web UI 要重新登录，最后会改回来）：

```powershell
conch passwd 临时密码123
```

约 5 秒后，Web UI 刷新时要求重新登录，用「临时密码123」能登进去。然后运行 `conch passwd 你的测试密码` 改回去。

- [ ] 9 通过

## 10. 系统代理

这一节会修改系统设置，做完会恢复。

**10.1 打开**

```powershell
conch sysproxy on
```

预期：

- 打印「系统代理已开启；daemon 退出时会恢复原来的设置」；
- 「设置 → 网络和 Internet → 代理」里，手动代理是 127.0.0.1:7890；
- 用 Edge 打开 <https://api.ipify.org>，显示代理的 IP；
- 打开 <http://192.168.1.1> 或其他内网地址时不走代理。

**10.2 关闭**

运行 `conch sysproxy off`。设置页恢复到 `proxy-before.txt` 里的样子。

**10.3 关掉 daemon 的窗口（本轮修复的问题）**

1. `conch sysproxy on`；
2. 直接点窗口 A 右上角的 ×，关掉它。

预期：系统代理恢复原样，网页能正常打开。

**10.4 强制结束进程**

1. 重新打开窗口 A，启动 daemon（4.2），运行 `conch sysproxy on`；
2. 运行 `taskkill /F /IM conch.exe`。

预期：系统代理还指向 127.0.0.1:7890，网页打不开。然后：

- `conch doctor` 显示「✗ 系统代理还指向 127.0.0.1:7890，但 conch 没有在运行……」；
- `conch doctor --fix` 显示「✓ 已恢复系统代理设置……」，设置页恢复原样。

**10.5 每次启动都是纯代理**

再启动 daemon。虽然上次结束时系统代理是开着的，这次启动后它仍然是关着的：conch 启动后只是 HTTP + SOCKS5 代理，开关只管一次运行。设置页应该和 `proxy-before.txt` 一样。

**10.6 在 profile 里要求开启**

1. 停掉 daemon；
2. 把 profile 里的 inbound 那一行改成 `inbound: { mixed-port: 7890, system-proxy: true }`；
3. 再启动 daemon。

预期：

- 系统代理一启动就指向 127.0.0.1:7890；
- 按 Ctrl+C 停掉后，恢复原样。

然后把那一行改回去。

- [ ] 10 通过

## 11. 换内核：xray 和 sing-box

**11.1 xray**

在窗口 A 按 Ctrl+C 停掉 daemon，然后运行 `conch daemon --backend xray`。

- `Test-Routes`：结果和 mihomo 一样（D 访问 Cloudflare 网站的已知情况除外）。
- Web UI 出口页：测速；在「出口」组里切换成员。
- Web UI 连接页：每条连接都有「命中」和出口路径。打开 baidu.com 这类走订阅规则的网站，「命中」也要写出具体是哪一条，例如「订阅 订阅 的规则 域名后缀 baidu.com」。
- 加一条路由（例如 `conch route add example.net E --for 5m`），大约 1 秒后生效。xray 改配置要重启内核，期间可能有一两个请求失败。
- `conch tun on`：预期报错，内容包含「xray 内核在这个系统上暂不支持 TUN」。xray 的 TUN 目前只在 Linux 上可用。

**11.2 sing-box**

Ctrl+C，然后运行 `conch daemon --backend sing-box`，把 11.1 的检查（TUN 那条除外）重做一遍。sing-box 改配置时也要重启内核，大约 0.5 秒内的请求会失败。

**11.3 记住内核**

Ctrl+C，然后运行不带 `--backend` 的 `conch daemon`。`conch status` 应该显示 sing-box，也就是上一次用的内核。

- [ ] 11 通过

## 12. TUN（需要管理员）

**12.1 以管理员身份启动**

在窗口 A 按 Ctrl+C。右键 PowerShell 或 Windows 终端，选「以管理员身份运行」。**用你平时登录的账号，不要换成另一个管理员账号。** 在这个窗口（窗口 C）里做 0.3，再运行：

```powershell
conch daemon --backend mihomo
```

**12.2 打开 TUN**

在窗口 B（普通权限）运行 `conch tun on`。预期：

- 成功，不弹防火墙提示；
- `netsh advfirewall firewall show rule name="Conch mihomo"` 能看到一条放行 mihomo.exe 的规则；
- `Get-NetAdapter` 里多出一块 TUN 网卡。

**12.3 TUN 下的流量**

这几条命令都不加 `-x`：

- `curl.exe -s https://api.ipify.org` 是默认出口的 IP；
- `curl.exe -s https://www.cloudflare.com/cdn-cgi/trace` 是本机 IP（DIRECT）；
- 浏览器什么都不用设就走代理；
- `nslookup www.google.com` 返回 198.18.x.x，这是 fake-ip，属于正常；
- 局域网（打印机、NAS、路由器管理页）能正常访问。

**12.4 关闭 TUN**

运行 `conch tun off`。预期：TUN 网卡消失，网络正常。

**12.5 没有权限时**

在普通权限的窗口里运行 daemon，再执行 `conch tun on`。预期报错：「没有创建 TUN 网卡的权限：需要管理员权限……」。

**12.6 sing-box**

用 sing-box（`--backend sing-box`，管理员窗口）把 12.2–12.4 重做一遍。防火墙规则这次叫「Conch sing-box」。

**12.7 强制结束**

TUN 开着时运行 `taskkill /F /IM conch.exe`。预期：网络在几秒内恢复，因为 TUN 网卡随内核一起消失。如果断网了，记录下来，然后运行 `conch doctor --fix`；还不行就重启电脑。

- [ ] 12 通过

## 13. 系统服务（需要管理员）

**13.1 安装**

先停掉所有 conch：窗口 A、窗口 C 都按 Ctrl+C。然后在管理员窗口运行：

```powershell
conch service install
```

预期：

- 打印「conch 服务已启动，日志在 C:\ProgramData\conch\conch.log」；
- 打印「agent 会在下次登录时自动启动」；
- 最后显示配置文件的位置和 Web UI 地址。

服务用的是 `C:\ProgramData\conch\profile.yaml`，安装时从你的 profile 复制过去。之后再改 `%APPDATA%\conch\profile.yaml`，**不会**影响服务。

**13.2 不用管理员也能看状态（本轮修复的问题）**

在普通窗口运行：

```powershell
conch service status       # conch 服务：运行中
Get-Service conch
conch status               # 内核运行中
Test-Routes
```

**13.3 文件权限（本轮修复的问题）**

```powershell
icacls C:\ProgramData\conch
```

预期只有 `NT AUTHORITY\SYSTEM` 和 `BUILTIN\Administrators`。在普通窗口运行 `Get-Content C:\ProgramData\conch\.env`，预期「拒绝访问」。

**13.4 Web UI**

用同一个密码能登录 <http://127.0.0.1:9277/>。

**13.5 agent**

1. 在普通窗口运行 `conch agent`；
2. 在 Web UI 里勾选「系统代理」。预期：agent 打印「系统代理已指向 127.0.0.1:7890」，设置页确认；
3. 取消勾选。预期：打印「已恢复原来的系统代理设置」；
4. 按 Ctrl+C 结束 agent。

**13.6 登录时自动启动（本轮修复的问题）**

在 Web UI 里打开系统代理，然后注销、重新登录。预期：

- 任务管理器里有 `conch.exe`（命令行带 `agent`）在运行；
- 登录时可能闪一下黑色窗口，但**不会**一直留着；
- `%LOCALAPPDATA%\conch\agent.log` 里有「系统代理已指向 127.0.0.1:7890」；
- 系统代理已经打开。

最后在 Web UI 里关掉系统代理。

**13.7 服务里的 TUN**

在 Web UI 里勾选 TUN，服务以 SYSTEM 身份运行，有权限。不加 `-x` 的 `curl.exe -s https://api.ipify.org` 应该走代理。然后取消勾选。

**13.8 服务运行时重新安装（本轮修复的问题）**

服务和 agent 都在运行时，在管理员窗口再执行一次 `conch service install`。预期：成功，服务重新启动。

**13.9 重启电脑**

预期：

- 服务自动启动，登录后 agent 也自动启动；
- 服务重新启动后是纯代理，系统代理是关着的（除非 `C:\ProgramData\conch\profile.yaml` 里写了 `inbound: { system-proxy: true }`）。

**13.10 卸载**

在管理员窗口运行：

```powershell
conch service uninstall
```

预期：

- 打印「已卸载 conch 服务。配置和数据还留在 C:\ProgramData\conch」；
- `Get-Service conch` 找不到这个服务；
- `netsh advfirewall firewall show rule name=all | findstr Conch` 没有输出；
- `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 里没有 `conch-agent`。

- [ ] 13 通过

## 14. 浏览器扩展

先在窗口 A 重新启动 `conch daemon`。

**14.1 加载扩展**

打开 `chrome://extensions`（Edge 是 `edge://extensions`），打开「开发者模式」，点「加载已解压的扩展程序」，选 `C:\conch-test\extension\chrome`。

**14.2 配对**

在任意网页上点扩展图标，出现配对页：

1. 地址填 `http://127.0.0.1:9277`；
2. 运行 `conch pair`，把 6 位码填进去。

预期：配对成功，顶部显示「mihomo · 运行中 · 分流」。

**14.3 当前网站**

打开 <https://www.youtube.com/>，点图标。预期：

- 显示出口、命中的规则和延迟；
- 把出口改成 C、有效期选 1 小时，提交后显示「已让 youtube.com 走 C」；
- `conch route list` 里有这条临时条目；
- 刷新 YouTube 之后，Web UI 连接页里 youtube 的连接走 C；
- 点「撤销」，条目消失。

**14.4 加载失败的网站**

点「开启：记录网页加载失败的网站」，允许权限，然后刷新网页。预期：

- 列出加载失败的域名；
- 被订阅规则屏蔽的广告域名（例如 doubleclick.net）显示「按规则屏蔽」，排在真正失败的后面；
- 点「分流…」，可以给这个域名指定出口。

**14.5 取消配对**

在 Web UI 概览页的「浏览器扩展」里能看到这次配对。取消它之后，再点扩展图标，回到配对页（「配对已失效」）。

**14.6 Firefox（可选）**

打开 `about:debugging` →「此 Firefox」→「临时载入附加组件」，选 `extension\firefox\manifest.json`，把 14.2–14.4 重做一遍。

- [ ] 14 通过

## 15. 清理

```powershell
conch sysproxy off              # 如果 daemon 还在运行
# 在窗口 A 按 Ctrl+C 停掉 daemon
conch doctor --fix
Remove-Item -Recurse $env:APPDATA\conch, $env:LOCALAPPDATA\conch    # 测试用的配置和数据，里面有你的节点
Remove-Item C:\conch-test\links.txt
```

如果装过服务，在管理员窗口运行：

```powershell
Remove-Item -Recurse C:\ProgramData\conch, "C:\Program Files\conch"
```

最后对照 `proxy-before.txt` 确认系统代理恢复了原样。

## 16. 记录问题

每个不通过的地方记下：

- 步骤编号（例如 10.3）；
- 看到了什么：命令输出直接复制，界面问题截图（截图前遮住 IP、链接）；
- `conch doctor` 的输出；
- daemon 窗口里的日志。服务模式下是 `C:\ProgramData\conch\conch.log`，agent 是 `%LOCALAPPDATA%\conch\agent.log`。

**不要**把节点链接、订阅地址、密码贴进 issue。
