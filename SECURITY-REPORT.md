# EduCodePass 客户端安全评估报告

> 目标：EduCodePass（东北大学「码途」C/C++ 闯关练习客户端）
> 版本：1.3.0（macOS）
> 方法：静态二进制分析 + 运行时符号追踪 + 注入验证
> 结论：**16 项问题** —— 2 项严重（1 项已修复、1 项未修复）、2 项高危、5 项中危、7 项低危/信息

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

**架构评价**：客户端壳**不承载业务逻辑**——题目、评测、评分、行为分析全部在远程前端 + 服务端。壳只负责：请求签名、设备指纹、环境检测、反作弊上报。这种设计降低了客户端被逆向的业务风险，但也意味着**所有本地检测都可以被绕过**（见下）。

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
| 修复建议 | 启动时对自身 Mach-O 计算哈希并与内嵌/服务端下发值比对；校验 `__TEXT` 段签名；校验加载的 dylib 列表 |

---

### V-03 · 证书 pinning 在 macOS 未实现（高危 · 未修复）

| 项 | 内容 |
|---|---|
| 证据 | 客户端 stderr 明确输出：`证书校验挂钩未安装（不影响启动）: 证书错误拦截未在 macOS 上实现（见 README 的「已知差距」第 2 条）` |
| 相关字段 | `publicKeyHashHex`（存在于二进制，但在 macOS 路径未启用校验） |
| 影响 | 理论上可对该客户端发起的 HTTPS 请求进行中间人观察/篡改（配合自签 CA） |
| 修复建议 | 在 macOS 网络栈实现 SPKI pinning；或至少校验服务端证书公钥哈希 |

---

### V-04 · 进程黑名单检测依赖外部命令，可轻易绕过（中危 · 未修复）

| 项 | 内容 |
|---|---|
| 机制 | 执行 `/bin/ps -A -o ucomm=` 获取进程列表，与本地名单（204 项）+ **服务端动态下发名单**（实测启动日志：`应用服务端下发的进程名单：65 条`）比对 |
| 内置命中示例 | `node`、`Terminal`、`nmap`、`Charles`、`osascript`、`ncat`、`Claude` |
| 绕过方式 | ① 将二进制内的 `/bin/ps` 字符串改为不存在的路径（如 `/bin/pX`）→ 扫描 exec 失败 → 返回空列表；② 或使用不在名单内的等价工具 |
| 影响 | 进程黑名单完全失效，且**客户端不会察觉**（无自校验，见 V-02） |
| 修复建议 | 改用 `libproc` / `sysctl(KERN_PROC)` 直接读进程表（不依赖外部命令）；对检测失败做失败即拒绝策略；名单改为服务端实时校验 |

---

### V-05 · DYLD 注入检测可被清除（中危 · 未修复）

| 项 | 内容 |
|---|---|
| 机制 | 检查环境变量 `DYLD_INSERT_LIBRARIES`，命中时记录 `环境变量被篡改` 位 |
| 客户端行为 | 日志：`检测到 DYLD_INSERT_LIBRARIES=...，已清除并记为环境异常` |
| 绕过方式 | 注入的 dylib 在 `__attribute__((constructor))` 中调用 `unsetenv("DYLD_INSERT_LIBRARIES")`（及 `DYLD_FORCE_FLAT_NAMESPACE` / `DYLD_LIBRARY_PATH`）→ 后续检测读到空值 |
| 影响 | 注入痕迹被清除，环境异常位不再置位 |
| 修复建议 | 在进程启动**最早阶段**（`main` 之前、`dyld` 回调）读取并留存一份环境快照；或改为检测 `_dyld_image_count()` 中非白名单镜像；或检测 `LC_LOAD_DYLIB` 异常 |

---

### V-06 · 环境检测位掩码可被内存修改（中危 · 未修复）

| 项 | 内容 |
|---|---|
| 机制 | 检测结果以 `u32` 位掩码记录在壳内（bss 区偏移 `+0xd04`），随上报发出 |
| 已知位 | `0x4` 截屏 / `0x20` 进程黑名单 / `0x40` 环境变量 / `0x100` 失焦 / `0x200` 环境篡改 |
| 绕过方式 | 注入后通过 `method_setImplementation` / 内存写入将对应位清零 |
| 影响 | 上报的异常位归零 |
| 修复建议 | 位掩码以只写方式维护（每次读取后立即重算）；增加位掩码的完整性校验（如与独立计数器交叉验证） |

---

### V-07 · 截屏监考基于外部命令，可被进程级欺骗（中危 · 未修复）

| 项 | 内容 |
|---|---|
| 机制 | 调用 `/usr/sbin/screencapture` 抓屏 + `/usr/bin/sips` 处理；触发时机见 §3.4 |
| 绕过方式 | 监控系统中是否出现 `screencapture` 进程，出现即隐藏作弊窗口，截图完成后恢复 |
| 影响 | 监考截图拍不到目标窗口 |
| 修复建议 | **改用 ScreenCaptureKit（`SCStream` / `SCScreenshotManager`）在进程内截图**，不 spawn 子进程 → 无进程名可被监控；同时对截图结果做完整性校验（如要求窗口列表快照与画面一致） |
| 备注 | 这是目前防护中最容易提升的一项：进程内截图可直接消除该绕过面 |

---

### V-08 · 窗口焦点检测可被 Swizzle 绕过（中危 · 未修复）

| 项 | 内容 |
|---|---|
| 机制 | 通过 `resignKeyWindow` / 前端 `blur` 事件判定「切屏」，计入 `envFlags 0x100` 与前端 `focusLostCount` |
| 绕过方式 | Swizzle `-[NSWindow resignKeyWindow]` 为 no-op（窗口永不 resignKey）+ 拦截前端 `blur` 监听 |
| 影响 | 切屏行为不再被记录 |
| 修复建议 | 改用 CGWindowList / ScreenCaptureKit 交叉验证「当前前台窗口是否为考试窗口」；前端计数与服务端心跳时间戳对齐校验 |

---

### V-09 · 设备指纹依赖单一标识（低危 · 未修复）

| 项 | 内容 |
|---|---|
| 机制 | `IOPlatformUUID`（硬件 UUID）+ Keychain `device_key` |
| 影响 | `IOPlatformUUID` 在虚拟化/容器环境可被伪造；Keychain 项在 adhoc 签名变更后可读性异常 |
| 修复建议 | 多维指纹组合（主板/网卡/磁盘序列号 + 安全隔区）并做一致性校验 |

---

### V-10 · 虚拟机检测仅依赖 sysctl（低危 · 未修复）

| 项 | 内容 |
|---|---|
| 机制 | `/usr/sbin/sysctl` 查询虚拟化标识 |
| 影响 | 可被 patch 或 hook；对容器/云主机识别有限 |
| 修复建议 | 多源交叉（`hv_vmm_present`、IOKit、CPU 特性、时序侧信道） |

---

### V-11 · 服务端下发名单可被探测与规避（信息）

| 项 | 内容 |
|---|---|
| 机制 | 启动日志输出 `应用服务端下发的进程名单：N 条`（实测 68 → 65 条，说明名单动态更新） |
| 影响 | 名单条目会泄露服务端关注范围；攻击者可据日志反推并更换工具 |
| 修复建议 | 不向前端/日志输出名单规模；名单在服务端比对而非下发 |

---

### V-12 · 前端行为计数依赖自证（信息）

| 项 | 内容 |
|---|---|
| 机制 | 前端上报 `focusLostCount`、`bulkInsertCount`、`untrustedEventCount`、`orphanInputCount`、`backspaceCount`、`inputIntervalCv`、`restoredCodeUnconfirmed` 等 |
| 影响 | 这些计数由**被测端自己生成**，理论上可被 JS 层篡改（但见 §3.5：签名保护了 body 完整性） |
| 正面评价 | 由于 `bodyHashHex` 签名机制（见下），body 篡改会被服务端识破——**这一点设计是正确的** |


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
| 修复建议 | ① 改用 **Secure Enclave** 生成不可导出密钥（`kSecAttrTokenIDSecureEnclave` + `kSecAccessControlBiometryAny`）；② 或至少用 `SecAccessControlCreateWithFlags` + `kSecAccessControlUserPresence`；③ 禁止用 `security` 命令行工具读写私钥 |

> 该问题与 V-01（硬编码工厂私钥）性质相近：**都是私钥泄露**。区别是 V-01 泄露的是所有设备通用的工厂私钥（1.3.0 已修），V-13 泄露的是**每台设备的独立身份私钥**，且**当前版本仍未修复**。

---

### V-14 · 配置下载地址可被环境变量劫持（信息级 · 未修复）

| 项 | 内容 |
|---|---|
| 机制 | 读取环境变量 `GOGO_CLIENT_CONFIG_URL` 作为配置下载地址（缺省为 `https://codepass.neusoft.edu.cn/api/client/config`） |
| 验证 | 设置该环境变量指向本地服务器后，客户端确实向该地址发起 `GET`（实测捕获：`User-Agent: curl/8.7.1`） |
| 影响 | 可**观察/重定向**客户端的配置请求；但因配置关键字段（`blockProcesses`）有**本地内置兜底**，实测无法通过伪造配置削弱检测 |
| 修复建议 | 生产构建忽略该环境变量；或对环境变量来源做校验；配置响应增加签名校验 |

---

### V-15 · 本地配置文件可篡改（低危 · 未修复）

| 项 | 内容 |
|---|---|
| 位置 | `~/Library/Application Support/gogo-client/config.json` |
| 权限 | `-rw-r--r--`，属主可写 |
| 字段 | `minVersion`、`blockProcesses`（进程黑名单）、`off` 等 |
| 验证 | 直接改写文件写入 canary 黑名单并重启，日志仍显示内置的 68 条 → **关键字段不影响运行时检测** |
| 影响 | 可篡改但**无法削弱防护**（有内置兜底）；仅影响配置类行为 |
| 修复建议 | 配置落盘时加签名/HMAC；启动时校验配置完整性 |


---

## 3. 防护机制完整盘点（供修复参考）

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

### 3.3 请求签名机制（设计正确，值得肯定）

```
前端:  body  →  SHA256  →  bodyHashHex
壳:    sign_request(method, bodyHashHex, nonce, timestamp, deviceId) → 设备私钥签名
服务端: 重算 body 哈希 → 比对 bodyHashHex → 验证签名 → 校验 nonce/timestamp
```

**该机制有效阻止了请求体篡改**：任何对 body 的修改都会导致 `bodyHashHex` 不匹配。这是本项目中**最扎实的一处设计**。

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

## 4. 修复优先级建议

| 优先级 | 项目 | 理由 |
|---|---|---|
| **P0** | 实现客户端二进制完整性自校验（V-02） | 一切本地防护的前提：二进制可改则所有检测可被消音 |
| **P0** | 截屏改用 ScreenCaptureKit（V-07） | 消除最容易实现的绕过面 |
| **P1** | 进程扫描改用 libproc（V-04） | 消除对 patch 单点字符串的依赖 |
| **P1** | macOS 实现证书 pinning（V-03） | 防止 MITM |
| **P1** | DYLD 检测提前到 dyld 回调（V-05） | 防止环境被清除 |
| **P2** | envFlags 只写 + 交叉校验（V-06） | 防止内存改位 |
| **P2** | 焦点检测改为窗口级交叉验证（V-08） | 防止 swizzle |
| **P3** | 指纹/虚拟化多维化（V-09、V-10） | 提升伪造成本 |

---

## 5. 版本差异（1.1.7 → 1.3.0）

逐字符串 diff 结论：

- **唯一实质变化**：移除硬编码工厂私钥，设备登记改为一次性登记码（V-01 修复）
- **反作弊检测面完全未变**：DYLD 检测、`/bin/ps` 扫描、`sysctl`、`screencapture`、`sips`、ioreg、Keychain、pinning、minisign、IPC 命令面，全部一致

**即：1.3.0 是一次安全加固（修私钥），但未针对上述绕过路径做任何改进。**

---

## 6. 披露说明

- 本报告用于**授权范围内的安全评估**，目的是帮助校方/厂商发现并修复问题。
- 报告中**未包含可直接运行的完整利用代码**，仅描述原理与复现要点。
- 所有验证均在**本地测试环境**完成，未对生产服务端发起攻击。
- 建议修复顺序见 §4；其中 **V-02（二进制完整性）** 与 **V-07（进程内截图）** 对整体防护水位提升最明显。

---

*报告生成时间：2026-10-16*
