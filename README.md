# WarpGameBoost

**Windows 上一键开启 Cloudflare WARP 游戏加速：自动优选 IPv6 入口，游戏流量（UDP）也走加速。**

## 解决什么问题

- **家里宽带打游戏时延迟忽高忽低、偶尔丢包**：运营商到游戏服务器的线路不一定好。经 Cloudflare 的网络转一下，往往更稳。
- **官方 WARP 客户端不能选入口**：它连哪个入口就是哪个，入口拥堵也不会换。本程序先用真正的 WireGuard 握手测一遍延迟、抖动和丢包，再连最好的那个。
- **浏览器代理管不到游戏**：游戏不认代理，对战数据走 UDP。本程序建一块虚拟网卡，整台电脑的流量（包括游戏）都经过 WARP。

## 怎么用

1. 从 [Releases](../../releases/latest) 下载 `WarpGameBoost.exe`。
2. 双击运行，同意管理员权限（建虚拟网卡需要）。
3. 等约 20 秒：自动注册免费 WARP 账号 → 优选入口 → 显示“✅ 加速已开启”。
4. 打开游戏。窗口里每 5 秒显示一次经隧道到 Cloudflare 的延迟。
5. 不玩了就关掉窗口（或按 Ctrl+C），网络立即恢复原样。

窗口里输入 `r` 回车可重新优选；当前入口失效时会自动换。

## 需要知道的

- **默认只用 IPv6 入口**，本机网络要有 IPv6（可在 [test-ipv6.com](https://test-ipv6.com/) 检查）。没有 IPv6 时会提示；加参数 `-ipv4` 可同时使用 IPv4 入口。
- **加速是全局的**：开着它时整台电脑都经过 WARP，网站和游戏看到的是 Cloudflare 的地址，游戏可能按新地址判断地区。
- **不一定更快**：线路本来就好的话，绕一下 Cloudflare 可能持平甚至略慢。先在游戏里看网络图（守望先锋按 Ctrl+Shift+N），开关各打几局对比。
- **Cloudflare 能看到你连了哪些服务器**（看不到加密内容）。
- 免费账号注册使用 WARP 官方 App 的同一接口（非公开 API），Cloudflare 可能随时更改或限制。
- 程序意外退出时，虚拟网卡和路由由系统随之清除，网络自动恢复。

## 文件

- `%LOCALAPPDATA%\WarpGameBoost\account.json`：WARP 账号和上次的优选结果。
- `wintun.dll`：首次运行时写在 exe 旁边，是 WireGuard 官方签名的虚拟网卡驱动 [Wintun](https://www.wintun.net/) 0.14.1。

## 校验

Releases 里的 exe 由 GitHub Actions 从本仓库源码编译，附构建来源证明：

```powershell
Get-FileHash .\WarpGameBoost.exe -Algorithm SHA256   # 与 SHA256SUMS.txt 对比
gh attestation verify .\WarpGameBoost.exe -R Freecode100Year/WarpGameBoost
```

每次构建都在 Windows 上实测：连接后整机流量确实经过 WARP（`warp=on`），强制结束进程后虚拟网卡被清除、网络恢复（`warp=off`）。

## 从源码构建

需要 Go（版本见 `go.mod`），并把 Wintun 0.14.1 的 `bin/amd64/wintun.dll` 放到源码目录：

```powershell
go build -trimpath -ldflags "-s -w" -o WarpGameBoost.exe .
```

## 许可证

MIT。使用 [wireguard-go](https://git.zx2c4.com/wireguard-go)（MIT）、[wireguard-windows](https://git.zx2c4.com/wireguard-windows) 的 winipcfg（MIT）和 Wintun（预编译签名版，按其许可随程序分发）。WARP 是 Cloudflare 的服务，本项目与 Cloudflare 无关。WARP 入口优选代码来自 [UltraLightBrowser](https://github.com/Freecode100Year/UltraLightBrowser)。
