# 节点在各个内核里怎么翻译

profile 是 conch 统一的配置，节点用 mihomo（Clash Meta）的写法。conch 把节点的每一项设置翻译成各个内核自己的写法；内核确实没有对应的，会报错或者说明怎么降级，不会悄悄丢掉。

下面的「✓」是照样翻译，「≈」是最接近的写法（编译时会给出警告），「✗」是这个内核做不到（编译时报错，提示换哪个内核）。trojan-go 节点，以及 xray、sing-box 上带 `ss-opts` 的 Trojan 节点，由 trojan-go 边车运行。

每个内核的写法都由 CI 交给真实内核检查（`internal/backend/testdata/*.profile.yaml` 生成的配置）。

## 协议

| 协议 | mihomo | xray | sing-box |
| --- | --- | --- | --- |
| ss、vmess、vless、trojan、socks5、http、hysteria2、wireguard | ✓ | ✓ | ✓ |
| hysteria（v1）、tuic（v5）、anytls、ssh | ✓ | ✗ | ✓ |
| direct、reject 节点 | ✓ | ✓ | ✓ |
| trojan-go | 边车 | 边车 | 边车 |
| tuic v4（token）、mieru、snell、ssr 等 | ✓ | ✗ | ✗ |

## 协议的细项

| 设置 | xray | sing-box |
| --- | --- | --- |
| ss 插件 obfs、shadow-tls | ✗ | ✓（shadow-tls 是一个前置出站） |
| ss 插件 v2ray-plugin | 只能关掉 mux（mihomo 默认开） | ✓ |
| ss 插件 gost-plugin、restls、kcptun | ✗ | ✗ |
| ss `udp-over-tcp` 和版本 | ✗（UDP 直接以 UDP 发往服务器） | ✓ |
| vmess `alterId` 不为 0 | ✗ | ✓ |
| vmess `authenticated-length`、`global-padding` | ✓（xray 总是 padding） | ✓ |
| `packet-encoding: packetaddr` | ≈ 用 xudp | ✓ |
| vless `encryption`（VLESS 加密） | ✓ | ✗ |
| vless `xtls-rprx-vision` | 写成 `-udp443`，像 mihomo 一样转发 UDP 443 | ✓ |
| trojan `ss-opts` | 边车 | 边车 |
| `smux`（sing-mux，含 Brutal） | ≈ 不用多路复用 | ✓ |
| hysteria2 端口跳跃 | ✓，但不能放在链里 | ✓ |
| hysteria2 跳跃间隔范围、gecko 混淆、BBR、QUIC 窗口 | ✓ | ✓ |
| hysteria2 `cwnd`、`udp-mtu` | ✗（警告后忽略） | ✗（警告后忽略） |
| wireguard `persistent-keepalive` | ✓ | ✓ |
| wireguard `workers` | ≈ 用 xray 自己的 | ✓ |
| wireguard 经由隧道解析域名（`remote-dns-resolve`、`dns`） | ✓（只用 IP 地址的普通 DNS） | ≈ 在本地解析 |
| wireguard 没开 `remote-dns-resolve`：在本地解析域名 | ✓ | ✓ |
| AmneziaWG 只发垃圾包（`jc`、`jmin`、`jmax`） | ✓（noise 掩码） | ✗ |
| AmneziaWG 改了协议的选项（`s1`、`h1`、`i1` 等） | ✗ | ✗ |

## TLS

| 设置 | xray | sing-box | trojan-go |
| --- | --- | --- | --- |
| SNI、ALPN、REALITY | ✓ | ✓ | REALITY ✗，ALPN 不生效 |
| `skip-cert-verify` | ≈ 正常校验（xray 删掉了这个选项） | ✓ | ✓ |
| `fingerprint`（证书指纹） | ✓ | ✓（conch 取到证书后换算） | ✓（同左） |
| `client-fingerprint`（uTLS） | ✓，`none` 是不用 | ✓ | 只有 chrome、firefox、ios，其他 ≈ 最接近的 |
| `ech-opts` | ✓（从 profile 的 DNS 查） | ✓ | ✗ |
| `name-cert-verify` | ✓ | ≈ 按 SNI 校验 | ✗ |
| 客户端证书 `certificate`、`private-key` | ✗ | ✓ | ✗ |

## 传输

| 设置 | xray | sing-box |
| --- | --- | --- |
| ws、gRPC | ✓ | ✓ |
| ws early data 放在请求头里 | ✓ | ✓ |
| ws early data 放在路径里（`early-data-header-name` 为空） | ≈ 不用 early data | ✓ |
| HTTPUpgrade | ✓（没有 early data） | ✓（没有 early data） |
| gRPC 的 User-Agent / 心跳 | ✓ / ✓ | ✗ / ✓ |
| h2 | ✗（xray 已移除） | ✓（需要 TLS） |
| TCP 上的 HTTP 伪装（方法、路径、Host、头） | ✓ | ✓（只用一个路径；不能套 TLS） |
| XHTTP 及其细项、`download-settings` | ✓ | ✗ |

## 拨号

`tfo`、`mptcp`、`interface-name`、`routing-mark`、`ip-version` 三个内核都能翻译（xray 用不回退到系统 DNS 的 `Force*` 策略）。trojan-go 边车只有 `ip-version: ipv4`。

## mihomo 不写出来的默认

xray 和 sing-box 需要写明的，conch 按 mihomo 的行为补上：

- vmess/vless 走 ws 加 TLS：ALPN 是 http/1.1，没写 servername 时用 ws 的 Host 当 SNI；走 h2、gRPC：ALPN 是 h2；
- trojan：ALPN 默认 h2、http/1.1，ws 默认 http/1.1；ws 的 Host 默认是 SNI；
- ws 路径里的 `?ed=N` 是 N 字节 early data；
- TCP 上的 HTTP 伪装默认 GET `/`，Host 是服务器地址；
- WireGuard 的 MTU 是 1408；
- 带宽：`100 Mbps` 是比特、`12 MBps` 是字节，不带单位是 Mbps；三个内核各按自己的写法得到同一个值；
- ss 插件：host 默认 bing.com，v2ray-plugin 默认开 mux，shadow-tls 默认第 2 版。

## 订阅

订阅可以是 Clash 配置、分享链接、sing-box 配置（JSON）或 SIP008。sing-box 配置里的出站按上面的对应关系反过来读成 mihomo 的写法（shadow-tls 前置出站读成 shadow-tls 插件）；只有 sing-box 的公钥指纹或信任的证书读不回来，会提示。出口组的 `filter`、`exclude-filter` 和 proxy-provider 的过滤用 mihomo 一样的正则（regexp2，支持前瞻）。

proxy-provider 的 `filter`、`exclude-filter`、`exclude-type`、`dialer-proxy` 和 `override`（设置项、`proxy-name` 改名、前后缀）照 mihomo 的顺序处理；`override-expr` 是 mihomo 自己的表达式，conch 做不到，会提示。分享链接里 conch 不认识的参数，添加时会提示。

## 各内核刻意保留的差别

这几处三个内核本来的默认就不一样，conch 不去统一：

- 节点没写 `client-fingerprint`：mihomo 和 sing-box 用 Go 自带的 TLS 握手，xray 模仿 Chrome（xray 的默认）。想三个内核一样，就在节点上写明 `client-fingerprint`。
- sing-box 的 hysteria2 默认模仿 Chrome 的 QUIC 握手，mihomo 和 xray 不会。sing-box 的文档说，服务器用 Ed25519 证书时这会连不上；遇到这种服务器请换用 mihomo 或 xray。
- 节点没写 `udp: true`（Clash 写法里大多数协议默认不开）：mihomo 会让 UDP 流量跳过指向它的规则、继续往下匹配；xray 和 sing-box 照样把 UDP 发给这个节点。
