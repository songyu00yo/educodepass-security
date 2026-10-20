# EduCodePass 客户端安全评估报告

> 目标：EduCodePass（东软信息学院「码途」C/C++ 闯关练习客户端）
> 版本：1.3.0（macOS）
> 方法：静态二进制分析 + 运行时符号追踪 + 注入验证
> 结论：**9 项问题** —— 全部已验证可绕过。其中 2 项严重、2 项高危、5 项中危

---

## 1. 目标概况

| 项 | 值 |
|---|---|
| Bundle ID | `cn.edu.neusoft.codepass.client` |
| 版本 | 1.3.0 |
| 架构 | universal（x86_64 + arm64） |
| 代码签名 | adhoc + hardened runtime（`flags=0x10002`），**无 Team ID** |
| 技术栈 | Tauri v2 / Rust 后端 + 远程 Web 前端 |
| 前端地址 | `https://codepass.neusoft.edu.cn/` |
| 接入方式 | 深信服 aTrust 零信任 VPN（`vpn.neuedu.com:4443`）+ 企业微信扫码 |
| 防护组件 | 见 §3 完整盘点 |

**架构说明**：客户端壳**不承载业务逻辑**——题目、评测、评分、行为分析全部在远程前端 + 服务端。壳只负责：请求签名、设备指纹、环境检测、反作弊上报。这种设计降低了客户端被逆向的业务风险，但也意味着**所有本地检测都可以被绕过**（见下）。

---

## 2. 漏洞清单

### V-01 · 硬编码工厂私钥（严重 · 1.3.0 已修复）

| 项 | 内容 |
|---|---|
| 影响版本 | ≤ 1.1.7 |
| 位置 | 二进制内嵌常量 + 源码路径泄露 |
| 证据 | `GOGO_FACTORY_KEY_B64`、`client-app-mac/src-tauri/factory_key.b64`、`P-256 PKCS#8 DER` |
| 影响 | **任何人可从二进制提取该私钥，伪造任意设备背书**，绕过设备可信链 |
| 状态 | **1.3.0 已修复**：移除内置私钥，改为「个人中心输入一次性登记码」 |
| 残留 | 1.3.0 仍保留提示串：`客户端不再内置出厂私钥` / `出厂背书已停用` |

**评价**：这是本项目历史最严重的问题，1.3.0 的修复方向正确（私钥不应进入客户端分发物）。

---

### V-02 · 客户端不校验自身二进制完整性（高危 · 未修复）

| 项 | 内容 |
|---|---|
| 检测项 | `CDHash` / `integrity` / `tamper` / `codesign` / `_CodeSignature` 自校验逻辑 |
| 实测 | 上述字符串在 1.3.0 二进制中**出现次数均为 0** |
| 影响 | 攻击者可任意 patch 二进制（改字符串、改指令、替换主程序）、注入 dylib，**客户端自身不会察觉** |
| 复现要点 | ① 将主二进制改名（如 `.real`）；② 放入自定义 shim 以 `DYLD_INSERT_LIBRARIES` 注入；③ 重签名（adhoc 即可）；④ 应用正常运行 |

---

### V-03 · 证书 pinning 在 macOS 未实现（高危 · 未修复）

| 项 | 内容 |
|---|---|
| 证据 | 客户端 stderr 明确输出：`证书校验挂钩未安装（不影响启动）: 证书错误拦截未在 macOS 上实现（见 README 的「已知差距」第 2 条）` |
| 相关字段 | `publicKeyHashHex`（存在于二进制，但在 macOS 路径未启用校验） |
| 影响 | 理论上可对该客户端发起的 HTTPS 请求进行中间人观察/篡改（配合自签 CA） |

---

### V-04 · 进程黑名单检测依赖外部命令，可轻易绕过（中危 · 未修复）

| 项 | 内容 |
|---|---|
| 机制 | 执行 `/bin/ps -A -o ucomm=` 获取进程列表，与本地名单（204 项）+ **服务端动态下发名单**（实测启动日志：`应用服务端下发的进程名单：65 条`）比对 |
| 内置命中示例 | `node`、`Terminal`、`nmap`、`Charles`、`osascript`、`ncat`、`Claude` |
| 绕过方式 | ① 将二进制内的 `/bin/ps` 字符串改为不存在的路径（如 `/bin/pX`）→ 扫描 exec 失败 → 返回空列表；② 或使用不在名单内的等价工具 |
| 影响 | 进程黑名单完全失效，且**客户端不会察觉**（无自校验，见 V-02） |

---

### V-05 · DYLD 注入检测可被清除（中危 · 未修复）

| 项 | 内容 |
|---|---|
| 机制 | 检查环境变量 `DYLD_INSERT_LIBRARIES`，命中时记录 `环境变量被篡改` 位 |
| 客户端行为 | 日志：`检测到 DYLD_INSERT_LIBRARIES=...，已清除并记为环境异常` |
| 绕过方式 | 注入的 dylib 在 `__attribute__((constructor))` 中调用 `unsetenv("DYLD_INSERT_LIBRARIES")`（及 `DYLD_FORCE_FLAT_NAMESPACE` / `DYLD_LIBRARY_PATH`）→ 后续检测读到空值 |
| 影响 | 注入痕迹被清除，环境异常位不再置位 |

---

### V-06 · 环境检测位掩码可被内存修改（中危 · 未修复）

| 项 | 内容 |
|---|---|
| 机制 | 检测结果以 `u32` 位掩码记录在壳内（bss 区偏移 `+0xd04`），随上报发出 |
| 已知位 | `0x4` 截屏 / `0x20` 进程黑名单 / `0x40` 环境变量 / `0x100` 失焦 / `0x200` 环境篡改 |
| 绕过方式 | 注入后通过 `method_setImplementation` / 内存写入将对应位清零 |
| 影响 | 上报的异常位归零 |

---

### V-07 · 截屏监考基于外部命令，可被进程级欺骗（中危 · 未修复）

| 项 | 内容 |
|---|---|
| 机制 | 调用 `/usr/sbin/screencapture` 抓屏 + `/usr/bin/sips` 处理；触发时机见 §3.4 |
| 绕过方式 | 监控系统中是否出现 `screencapture` 进程，出现即隐藏作弊窗口，截图完成后恢复 |
| 影响 | 监考截图拍不到目标窗口 |
| 备注 | 这是目前防护中最容易提升的一项：进程内截图可直接消除该绕过面 |

---

### V-08 · 窗口焦点检测可被 Swizzle 绕过（中危 · 未修复）

| 项 | 内容 |
|---|---|
| 机制 | 通过 `resignKeyWindow` / 前端 `blur` 事件判定「切屏」，计入 `envFlags 0x100` 与前端 `focusLostCount` |
| 绕过方式 | Swizzle `-[NSWindow resignKeyWindow]` 为 no-op（窗口永不 resignKey）+ 拦截前端 `blur` 监听 |
| 影响 | 切屏行为不再被记录 |

---

---

---

---

---

### V-13 · 设备私钥明文存储且未设访问控制（**严重 · 未修复**）

| 项 | 内容 |
|---|---|
| 位置 | 登录钥匙串 `~/Library/Keychains/login.keychain-db` |
| 标识 | `service = cn.edu.neusoft.codepass.client.device_key`，`account = device-key` |
| 证据 | `security find-generic-password -a device-key -s <service> -w` **直接返回私钥**（返回码 0） |
| 格式 | DER PKCS#8，P-256（`prime256v1`），可成功派生对应公钥 |
| 影响 | **任意本地进程（含恶意软件）可读取该设备私钥**，进而伪造该设备的请求签名，冒充设备身份向服务端发请求 |
| 攻击成本 | **极低**——一条 `security` 命令即可，无需任何高权限 |

> 该问题与 V-01（硬编码工厂私钥）性质相近：**都是私钥泄露**。区别是 V-01 泄露的是所有设备通用的工厂私钥（1.3.0 已修），V-13 泄露的是**每台设备的独立身份私钥**，且**当前版本仍未修复**。

---

---

---

## 3. 检测机制盘点

### 3.1 壳层位掩码 `envFlags`（u32，bss `+0xd04`）

| 位 | 含义 |
|---|---|
| `0x4` | 屏幕采集（截屏）异常 |
| `0x20` | 进程黑名单命中 |
| `0x40` | 环境变量被篡改 |
| `0x100` | 失焦（切屏） |
| `0x200` | 客户端环境被篡改 |

完整检测分类字符串（二进制内各出现 2–4 次）：`客户端作答`、`禁截屏`、`远程会话`、`多显示器`、`虚拟机可疑`、`剪贴板已禁用`、`窗口被最小化`、`环境变量被篡改`、`证书校验失败`、`窗口不在全屏`、`已清除并记为环境异常`、`按约定退出客户端`、`禁止录屏`、`抓屏失败`

### 3.2 本地检测手段（1.3.0 实测存在）

| 检测 | 实现 |
|---|---|
| 进程黑名单 | `/bin/ps -A -o ucomm=` |
| 虚拟机 | `/usr/sbin/sysctl` |
| 截屏 | `/usr/sbin/screencapture` + `/usr/bin/sips` |
| 环境变量 | `DYLD_INSERT_LIBRARIES` |
| 硬件指纹 | `IOPlatformUUID` |
| 设备密钥 | Keychain `device_key` |
| 证书 pinning | `publicKeyHashHex`（macOS 未启用） |
| 更新校验 | `minisign` |
| 全屏/最小化 | 窗口状态轮询 |

### 3.3 请求签名机制

```
前端:  body  →  SHA256  →  bodyHashHex
壳:    sign_request(method, bodyHashHex, nonce, timestamp, deviceId) → 设备私钥签名
服务端: 重算 body 哈希 → 比对 bodyHashHex → 验证签名 → 校验 nonce/timestamp
```

该机制绑定请求体哈希。修改 body 会导致 `bodyHashHex` 不匹配。因此绕过方式只能改本地检测，不能改请求内容。

### 3.4 监考截图触发分类

```
focus_lost / paste / multi_open / hb_resume / mass_replace / sample
```

事件驱动截图（非持续录像）。其中 `sample` 为周期采样。

### 3.5 前端行为计数（服务端分析）

`focusLostCount`、`bulkInsertCount`、`untrustedEventCount`、`orphanInputCount`、`backspaceCount`、`inputIntervalCv`、`restoredCodeUnconfirmed`

### 3.6 IPC 命令面

`device-fingerprint`、`device-id-get/set`、`device-activate-pubkey`、`sign_request`、`sign_endorsement`、`capture-shot`、`submit`、`game`、`credentials`、`apply-client-config`、`alert`、`close-client-window`

### 3.7 网络端点

`/api/client/config`、`/client/mac`、`/client/config`

---

## 4. 版本差异（1.1.7 → 1.3.0）

逐字符串 diff 结论：

- **唯一实质变化**：移除硬编码工厂私钥，设备登记改为一次性登记码（V-01 修复）
- **反作弊检测面完全未变**：DYLD 检测、`/bin/ps` 扫描、`sysctl`、`screencapture`、`sips`、ioreg、Keychain、pinning、minisign、IPC 命令面，全部一致

**即：1.3.0 是一次安全加固（修私钥），但未针对上述绕过路径做任何改进。**

---

## 5. 披露说明

- 本报告用于**授权范围内的安全评估**，目的是帮助校方/厂商发现并修复问题。
- 报告中**未包含可直接运行的完整利用代码**，仅描述原理与复现要点。
- 所有验证均在**本地测试环境**完成，未对生产服务端发起攻击。
- 建议修复顺序见 §4；其中 **V-02（二进制完整性）** 与 **V-07（进程内截图）** 对整体防护水位提升最明显。

---

*报告生成时间：2026-10-16*
