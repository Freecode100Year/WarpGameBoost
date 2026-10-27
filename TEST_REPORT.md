# WarpGameBoost v0.9.1 本地构建测试报告

构建日期：2026-10-27。基础提交：0ee9c0d13779c2eedbdc0af22e55fda383e6c9c6（v0.9.0）。
源码位置：/root/WarpGameBoost，分支 fix/v0.9.1。本次修改尚未推送到 GitHub。

## 修复与回归验证

- 损坏账号：原有加载逻辑接受无效 Base64、长度错误及低阶服务器公钥和缺失/错误地址。回归测试先失败，修复后通过；注册回复复用同一校验。
- 扫描输入：原版无地址族时出现 crypto/rand 参数异常，空账号时空指针崩溃。修复后直接返回空结果；非正数扫描数量不发包。
- 握手探测：本地 UDP 服务返回接收索引不匹配的 92 字节回复，原版错误报告可达、零丢包；修复后不计为有效回复。旧包后收到当前回复的测试通过。
- 参数校验提前到注册之前，拒绝非正数 -count。
- 探测测试验证消息格式和索引关联，不代表对握手回复增加了密码学认证。

## 已完成检查

环境：Linux amd64，Go 1.26.0；Windows 目标为 GOOS=windows GOARCH=amd64 CGO_ENABLED=0。

| 检查 | 结果 |
| --- | --- |
| go test -v ./... | 13 个测试函数及其子测试通过 |
| go test -count=1 -cover ./... | 通过，Linux 通用代码语句覆盖率 64.2% |
| go test -race -count=1 ./... | 通过，无竞态报告 |
| go vet ./... | 通过 |
| GOOS=windows GOARCH=amd64 go vet ./... | 通过 |
| go mod verify | all modules verified |
| git diff --check | 通过 |
| Windows x64 交叉编译 | 通过，PE32+ console executable |
| EXE 自身 .rsrc 版本资源 | 0.9.1.0 |
| EXE 自身管理员权限声明 | requireAdministrator 存在 |
| 独立代码审查 | 未发现重要缺陷 |

Wintun 0.14.1 原始压缩包 SHA256：
07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
与仓库 CI 配置一致。amd64 DLL 已嵌入 EXE，源码包同时包含该 DLL、许可证及生成的 Windows 资源对象。

## 未完成的 Windows 运行检查

Wine 启动命令 `wine WarpGameBoost.exe -version` 退出码 2，Go 运行时在进入 main 前报错：
`fatal error: bcryptprimitives.dll not found`。
这是当前 Wine 环境的限制。本报告没有确认 Windows 上的 -version 输出、提权、Wintun 网卡、真实 WARP 连接、DNS、生效后的速度或退出恢复。
本次 EXE 是本地测试构建，没有 GitHub Actions 来源证明；不得将仓库历史 CI 的结果视为本版本实测结果。

请在 Windows 上完成以下实测：

1. 执行 `./WarpGameBoost.exe -version`，确认显示 WarpGameBoost 0.9.1。
2. 管理员 PowerShell 执行 `./WarpGameBoost.exe -selftest -count 80`，确认退出码 0，且退出后无 WarpGameBoost 网卡。
3. 分别执行 `-selftest -exit ipv4 -count 80` 和 `-selftest -exit ipv6 -dns system -count 80`。
4. 正常运行，确认双栈 WARP 出口、恶意软件 DNS、输入 r 重新优选、输入 q 退出恢复网络；再验证关闭窗口、强制结束及切换网络。

## 构建方式

源码包含已生成的 amd64 Windows 资源对象和 wintun.dll。在 Windows 且安装 go.mod 指定 Go 版本后：

```powershell
go test ./...
go vet ./...
go build -trimpath -ldflags "-s -w -buildid= -X main.version=0.9.1" -o WarpGameBoost.exe .
```

本次 Linux 实际构建使用同样的编译参数，并设置 GOOS=windows GOARCH=amd64 CGO_ENABLED=0。
资源由 github.com/tc-hib/go-winres@v0.3.3 生成，版本 0.9.1，使用 cli/admin manifest。
