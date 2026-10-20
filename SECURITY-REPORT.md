# EduCodePass 客户端安全评估

> 目标：EduCodePass（东软信息学院「码途」C/C++ 闯关练习客户端）macOS 版
> 版本：1.3.0
> 样本 SHA-256：`5a3a07ebae2df12f4ea9676f9675e8547413369f3059c7bae6e27b5341d07b5d`
> 二进制大小：13,999,632 字节（universal：x86_64 + arm64）
> 测试环境：macOS 27.2（26B5112a），arm64，Apple M1 Pro

## 结论与统计口径

本次评估针对 1.3.0。

**记录 8 项当前版本存在的问题**，另附 **1 项历史问题**（1.1.7 存在，1.3.0 已修复，仅作背景）。

| 编号 | 问题 | 严重程度 | 验证方式 |
|---|---|---|---|
| V-13 | 设备私钥可被同用户进程读取 | 严重 | 动态实测 |
| V-02 | 未发现二进制完整性校验 | 高 | 静态分析 + 动态实测 |
| V-16 | IPC ACL 配置不一致 | 高 | 动态实测 |
| V-04 | 进程黑名单依赖外部命令 | 中 | 静态分析 + 动态实测 |
| V-05 | DYLD 检测可被清除 | 中 | 静态分析 + 动态实测 |
| V-06 | 环境位掩码可被改写 | 中 | 静态分析（未验证） |
| V-07 | 截屏监考可被进程监控欺骗 | 中 | 静态分析（存在时序竞争） |
| V-08 | 窗口焦点检测可被 Swizzle 绕过 | 中 | 静态分析 + 动态实测 |
| V-01 | 硬编码工厂私钥 | **历史问题** | 静态分析（1.3.0 已移除） |

**标注说明**

- **动态实测**：在本机实际执行并观察到结果。
- **静态分析**：从二进制字符串或结构推断，未做运行时验证。
- 静态分析不能证明某个机制不存在，只能说明未发现。每条都写明了这一点。

## 1. 目标概况

| 项 | 值 |
|---|---|
| Bundle ID | `cn.edu.neusoft.codepass.client` |
| 版本 | 1.3.0 |
| 架构 | universal（x86_64 + arm64） |
| 代码签名 | adhoc + hardened runtime（`flags=0x10002`），无 Team ID |
| 技术栈 | Tauri v2 / Rust 后端 + 远程 Web 前端 |
| 前端 | `https://codepass.neusoft.edu.cn/` |
| 接入 | 深信服 aTrust 零信任 VPN + 企业微信扫码 |
| 主二进制 | `educodepass` |

客户端壳不承载业务逻辑。题目、评测、评分、行为分析都在远程前端和服务端。壳只做四件事：请求签名、设备指纹、环境检测、反作弊上报。

## 2. 漏洞清单

### V-13 · 设备私钥可被同用户进程读取（严重 · 动态实测）

| 项 | 内容 |
|---|---|
| 位置 | 登录钥匙串，`service = cn.edu.neusoft.codepass.client.device_key`，`account = device-key` |
| 测试条件 | 普通用户，非 root；进程为 `/usr/bin/security`（系统自带工具，非客户端进程）；同一登录会话 |
| 观察结果 | `security find-generic-password -a device-key -s <service> -w` 返回码 0，无 GUI 授权提示，直接输出私钥 |
| 格式 | DER PKCS#8，P-256（`prime256v1`），约 184 字符 base64，可派生对应公钥 |
| 影响 | 同用户会话下的进程可读取该私钥，进而产生该设备的有效签名 |
| 成立条件 | ① 攻击者已在同一登录会话中获得代码执行能力；② 该钥匙串项未配置访问控制（实测未见 ACL 段） |
| **局限** | ① 未测试跨用户、沙箱化应用、启用 SIP 限制的场景；② 私钥可签名不等于服务端接受任意操作，请求仍需通过登录态与权限校验 |
| 缓解方向 | 改用 Secure Enclave 生成不可导出密钥，或至少给钥匙串项配置访问控制 |

### V-02 · 未发现二进制完整性校验（高 · 静态分析 + 动态实测）

| 项 | 内容 |
|---|---|
| 验证方式 | 先静态找校验特征，再实际修改二进制观察是否被阻止 |
| 静态证据 | 二进制内 `CDHash`、`integrity`、`tamper`、`codesign`、`_CodeSignature` 字符串计数均为 0 |
| 动态证据 | 将 `/bin/ps` 改为 `/bin/pX`（2 处，两个架构各一），重新签名后客户端**正常启动、正常提交**，未观察到完整性告警或拒绝 |
| 影响 | 修改客户端二进制并重签名后，客户端不阻止运行 |
| 成立条件 | 修改后需重签名（adhoc 即可，无需开发者证书） |
| **局限** | 静态找不到字符串不能证明校验不存在。可能存在：① 以数值常量而非字符串实现的校验；② 仅在特定操作时触发的校验；③ 服务端侧的完整性判定。本次只验证了「启动 + 提交」这条路径未被阻止 |
| 缓解方向 | 对 `__TEXT` 段做哈希并与内嵌或服务端下发值比对；校验已加载 dylib 列表 |

### V-16 · IPC ACL 配置不一致（高 · 动态实测）

| 项 | 内容 |
|---|---|
| 背景 | 页面 JS 中 `window.__TAURI__.core.invoke` 可用（实测 `invoke-ok`） |
| 测试方法 | 从页面上下文调用各 IPC 命令，按返回的错误类型区分 ACL 拒绝与参数校验失败 |
| 影响 | 页面上下文可调用部分高风险命令。若能注入 JS（XSS、恶意扩展、被篡改的前端资源），可借此操作客户端内部能力 |

**ACL 边界实测结果**

| 命令 | 结果 | 判定 |
|---|---|---|
| `device_id_get` | 返回成功 | ACL 放行 |
| `device_fingerprint` | 返回成功 | ACL 放行 |
| `device_pubkey` | 返回成功 | ACL 放行 |
| `sign_request` | `not allowed by ACL` | **拒绝** |
| `sign_endorsement` | `invalid args method` | ACL 放行，仅缺参数 |
| `apply_client_config` | `invalid args blockProcesses` | ACL 放行，仅缺参数 |
| `open_client_window` | `invalid args url` | ACL 放行，仅缺参数 |
| `sign_set_key` | `invalid args key` | ACL 放行，仅缺参数 |

**判定依据**：Tauri v2 先检查 ACL 再做参数反序列化。因此 `not allowed by ACL` 表示权限拒绝，`invalid args` 表示权限已通过、只是参数不匹配。

**关键点**：`sign_request` 被正确限制，但 `sign_set_key`（替换签名密钥）未限制。两者权限应当同级。

**局限**：`sign_set_key`、`open_client_window`、`apply_client_config` 只验证到「权限放行 + 参数校验」这一步，**未实际传入完整参数执行**。原因：`sign_set_key` 会替换设备密钥，`open_client_window` 会触发 `multi_open` 截图分类。所以「可调用」是证明的，「调用后产生什么效果」未验证。

### V-04 · 进程黑名单依赖外部命令（中 · 静态分析 + 动态实测）

| 项 | 内容 |
|---|---|
| 机制 | 执行 `/bin/ps -A -o ucomm=` 获取进程名，与内置名单比对（服务端下发，实测 65–69 条，数量随配置变动） |
| 动态证据 | 将二进制内 `/bin/ps` 改为 `/bin/pX` 后，扫描无法取得进程列表 |
| 影响 | 进程黑名单检测失效，且客户端不报错 |
| 成立条件 | 需要修改二进制并重签名（依赖 V-02） |
| **局限** | 只验证了「改字符串」这一条路径。未验证是否存在不依赖 `/bin/ps` 的补充检测 |
| 缓解方向 | 改用 `libproc` / `sysctl(KERN_PROC)` 直接读进程表 |

### V-05 · DYLD 检测可被清除（中 · 静态分析 + 动态实测）

| 项 | 内容 |
|---|---|
| 机制 | 检查环境变量 `DYLD_INSERT_LIBRARIES`，命中时记录环境异常位 |
| 动态证据 | 注入的 dylib 在 constructor 中调用 `unsetenv` 清除该变量，客户端后续检测读到空值，未记录异常 |
| 影响 | 注入痕迹不被该检测捕获 |
| 成立条件 | 注入代码需在客户端检测之前执行（constructor 满足） |
| **局限** | 只绕过这一项环境变量检测。若存在对已加载镜像列表（`_dyld_image_count`）的检查，本方法不覆盖 |

### V-06 · 环境位掩码可被改写（中 · 静态分析，未验证）

| 项 | 内容 |
|---|---|
| 机制 | 检测结果以 `u32` 位掩码存放于壳内 bss 区（偏移 `+0xd04`），随上报发出 |
| 已知位 | `0x4` 截屏 / `0x20` 进程黑名单 / `0x40` 环境变量 / `0x100` 失焦 / `0x200` 环境篡改 |
| 影响 | 理论上可改位清零 |
| **局限** | 本条为静态推断，未做运行时验证。且因 V-04、V-05 已让对应位不置位，无需实际改写。改内存是最容易被交叉校验发现的路径，本次未采用 |

### V-07 · 截屏监考可被进程监控欺骗（中 · 静态分析）

| 项 | 内容 |
|---|---|
| 机制 | 调用 `/usr/sbin/screencapture` 抓屏，`/usr/bin/sips` 处理。触发分类：`focus_lost`、`paste`、`multi_open`、`hb_resume`、`mass_replace`、`sample` |
| 影响 | 监控 `screencapture` 进程出现即隐藏窗口，可让截图内容不含目标窗口 |
| **时序局限（重要）** | 这是一种时序竞争，不是确定性保证：① 轮询间隔（如 0.1 s）内截屏可能已完成；② 从检测到进程启动到窗口隐藏存在窗口期；③ `screencapture` 可能被多次调用或采用不同参数。实际成功率取决于轮询频率、截图耗时与窗口合成延迟，本次未做成功率统计 |
| 缓解方向 | 改用 ScreenCaptureKit 在进程内截图，消除进程名可监控这条面 |

### V-08 · 窗口焦点检测可被 Swizzle 绕过（中 · 静态分析 + 动态实测）

| 项 | 内容 |
|---|---|
| 机制 | `-[NSWindow resignKeyWindow]` 被调用即视为切屏，计入 `envFlags 0x100` 与前端 `focusLostCount` |
| 动态证据 | 将该方法替换为空实现后，切换前台应用未触发失焦记录 |
| 影响 | 切屏行为不被该项检测捕获 |
| **局限** | 只覆盖 `resignKeyWindow` 这一条路径。若存在窗口层级或 `CGWindowList` 侧的交叉验证，本方法不覆盖 |

## 3. 历史问题

### V-01 · 硬编码工厂私钥（1.1.7 存在，1.3.0 已修复）

| 项 | 内容 |
|---|---|
| 影响版本 | ≤ 1.1.7 |
| 现状 | 1.3.0 二进制中已无 `GOGO_FACTORY_KEY_B64`、`factory_key.b64`，改为一次性登记码 |
| 保留原因 | 作为背景记录，说明该类问题在本项目中出现过 |

## 4. 附注：未计入问题清单的观察

**V-03 缺少证书 pinning**（信息级）

客户端 stderr 输出：`证书校验挂钩未安装（不影响启动）: 证书错误拦截未在 macOS 上实现`。

这不等同于 HTTPS 失效。普通证书链验证仍然有效，自签名证书依然会被拒绝。缺少 pinning 只意味着：如果攻击者能让系统信任其 CA，则可以中间人观察。

由于这一条需要额外前提（安装受信任 CA），且未做实际验证，不计入问题清单。

## 5. 检测机制盘点

### 5.1 环境位掩码（u32，bss `+0xd04`）

| 位 | 含义 |
|---|---|
| `0x4` | 屏幕采集异常 |
| `0x20` | 进程黑名单命中 |
| `0x40` | 环境变量被篡改 |
| `0x100` | 失焦 |
| `0x200` | 客户端环境被篡改 |

### 5.2 本地检测手段（1.3.0 实测存在）

| 检测 | 实现 |
|---|---|
| 进程黑名单 | `/bin/ps -A -o ucomm=` |
| 虚拟机 | `/usr/sbin/sysctl` |
| 截屏 | `/usr/sbin/screencapture` + `/usr/bin/sips` |
| 环境变量 | `DYLD_INSERT_LIBRARIES` |
| 硬件指纹 | `/usr/sbin/ioreg`（IOPlatformUUID）、`/usr/sbin/system_profiler` |
| 设备密钥 | 钥匙串 `device_key` |
| 证书 pinning | `publicKeyHashHex`（macOS 未启用） |
| 更新校验 | minisign（内嵌公钥） |

### 5.3 请求签名机制

```
body → SHA256 → bodyHashHex
壳：sign_request(method, bodyHashHex, nonce, timestamp, deviceId) → 设备私钥签名
服务端：重算 body 哈希比对，再验签
```

**签名输入的确切构造未验证**。`sign_request` 被 ACL 拒绝，页面无法调用；二进制已 strip，静态也拿不到。因此「只签 bodyHashHex」还是「签多字段拼接」目前无法确认。

**可确认的部分**：修改 body 会使 `bodyHashHex` 不匹配。这一点从机制设计上成立。

### 5.4 IPC 命令面（23 个，含 ACL 配对）

`apply_client_config`、`capture_shot`、`close_client_window`、`device_activate_pubkey`、`device_fingerprint`、`device_id_get/set`、`device_pubkey`、`install_update`、`open_client_window`、`sign_request`、`sign_endorsement`、`sign_set_key`

### 5.5 更新机制

```
端点：https://codepass.neusoft.edu.cn/client/mac/latest-mac.json
校验：minisign（内嵌公钥）
错误处理：包含 Invalid encoding in minisign data / The signature verification failed /
         Unexpected signature algorithm / different key than the one provided 等
```

## 6. 版本差异（1.1.7 → 1.3.0）

- 移除硬编码工厂私钥，设备登记改为一次性登记码
- 反作弊检测面未变：DYLD 检测、`/bin/ps` 扫描、`sysctl`、`screencapture`、`sips`、ioreg、钥匙串、pinning、minisign、IPC 命令面，均一致

## 7. 披露说明

- 本报告在授权范围内完成。所有验证在本机测试环境进行，未对生产服务端发起攻击。
- 每个结论标注了验证方式。静态分析得出的结论均标明局限，不能当作「机制不存在」的证明。
- 报告已脱敏：用户名、设备登记码、API 密钥、个人标识均已移除。
- 本报告不含完整利用代码，也不含修复方案。

---

*报告生成时间：2026-10-16*
