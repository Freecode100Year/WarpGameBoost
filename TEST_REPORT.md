# WarpGameBoost v0.9.1 测试报告

构建日期：2026-10-27。基础提交：0ee9c0d13779c2eedbdc0af22e55fda383e6c9c6（v0.9.0）。
初始本地源码位置：/root/WarpGameBoost，开发分支 fix/v0.9.1。修复源码已推送到 GitHub。

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

## Windows 预发布验证（全部通过）

运行：https://github.com/Freecode100Year/WarpGameBoost/actions/runs/40591867418

测试提交：259067cd5d520fba0faa7405b6176f704958d499。后续发布准备仅更新文档，程序源码相同。
GitHub Actions windows-latest 的完整流程结果为 success，确认：

- Windows 原生 go vet、完整单元测试及编译通过。
- 程序 -version 输出和文件版本资源校验通过。
- 仅 IPv6 出口（system DNS）、仅 IPv4 出口的真实隧道测试通过。
- 默认双栈出口均为 warp=on，恶意软件 DNS 与常规域名解析测试通过。
- 强制结束后虚拟网卡清理、DNS 恢复、网络恢复 warp=off 通过。
- 官方 WARP 客户端已连接时，程序自动断开它并连接自己的隧道通过。

该测试机没有原生 IPv6，因此仍未验证真实 IPv6 入口；Wi-Fi 切换、睡眠唤醒及手动提权窗口也不在此次 CI 验证范围。正式 v0.9.1 标签流程会再次运行上述检查，再自动发布 EXE。

## 初始本地 Wine 检查（历史记录）

Wine 启动命令 `wine WarpGameBoost.exe -version` 退出码 2，Go 运行时在进入 main 前报错：
`fatal error: bcryptprimitives.dll not found`。
这是初始本地 Wine 环境的限制，后续已通过上文的 Windows 原生 CI 验证。初始 Linux 交叉编译 EXE 与正式 Release 的 Actions EXE 是不同构建，校验值不可混用。CI 不代表真实游戏速度测量。

用户可在自己的 Windows 网络环境复验：

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
