# EduCodePass 客户端安全评估

[返回项目首页](README.md) · [查看技术报告](SECURITY-REPORT-FULL.md)

## 评估信息

| 项目 | 说明 |
| --- | --- |
| 目标 | EduCodePass macOS 客户端，东软信息学院“码途”C/C++ 闯关练习客户端 |
| 版本 | **1.3.2**（对照基线 1.3.0） |
| 架构与大小 | x86_64、arm64；1.3.2 为 14,049,600 字节，1.3.0 为 13,999,632 字节 |
| 测试环境 | macOS，arm64（Apple Silicon），本机 |
| 代码签名 | adhoc + hardened runtime（`flags=0x10002`），无 Team ID |
| 前端构建戳 | `*-202610230039.js`（52 个 chunk） |
| 更新清单 | `pub_date 2026-10-22T01:57:22Z`，`version 1.3.2` |

环境信息为本次实测采集。1.3.0 基线的环境信息沿用原记录。

## 结论与统计口径

本次评估针对 1.3.2，并对 1.3.0 基线的 8 项发现逐条复核。

记录 **14 项**安全发现：8 项为基线复核结果，6 项为 1.3.2 新增。另附 1 项历史问题（V-01，1.1.7 存在，1.3.0 已修复，1.3.2 维持修复）。

严重程度沿用原报告评级，验证状态单独列出。统计包含待验证项，不代表各项影响均已复现。

| 编号 | 问题 | 严重程度 | 1.3.0 | 1.3.2 | 验证方式 |
| --- | --- | --- | --- | --- | --- |
| V-13 | 设备私钥可被同用户进程读取 | 严重 | 存在 | **存在** | 基线动态实测 + 本次静态补证 |
| V-02 | 未发现二进制完整性校验 | 高危 | 存在 | **存在** | 静态分析 + 动态实测 |
| V-16 | IPC ACL 配置不一致 | 高危 | 存在 | **语义变化** | 动态实测 |
| V-17 | `sign_request` 对页面脚本开放，可签出 ECDSA 签名 | 高危 | 不存在 | **新增** | 动态实测 |
| V-04 | 进程黑名单依赖外部命令 | 中危 | 存在 | **存在** | 静态分析 + 动态实测 |
| V-05 | DYLD 检测可被清除 | 中危 | 存在 | **存在** | 静态分析 + 动态实测 |
| V-06 | 环境位掩码改写风险 | 中危 | 未验证 | **未验证** | 静态分析 |
| V-07 | 截屏进程监控存在时序竞争 | 中危 | 静态 | **静态** | 静态分析 |
| V-08 | 窗口焦点检测可被 Swizzle 绕过 | 中危 | 存在 | **存在** | 静态分析 + 动态实测 |
| V-18 | 设备指纹明细对页面脚本开放 | 中危 | 部分 | **加重** | 动态实测 |
| V-19 | 配置下发端点无鉴权、请求无签名 | 中危 | 未记录 | **新增** | 动态实测 + 静态分析 |
| V-20 | 行为指标全前端计算，签名不覆盖真实性 | 低危 | 存在 | **存在** | 静态分析 |
| V-21 | 新增镜像注入检测，判据仅为路径前缀 | 中危 | 无此检测 | **新增** | 动态实测 |
| V-22 | 新增截屏产物自检 | 中危 | 无此检测 | **新增** | 静态分析 |
| V-01 | 硬编码工厂私钥 | 历史 | 已修复 | **仍已修复** | 静态分析 |

标注说明：

- 动态实测：在本机实际执行并观察到结果。
- 静态分析：从二进制字符串、反汇编或前端包推断，未做运行时验证。
- 未检出某个特征，不能证明对应机制不存在。静态推断需结合运行时证据判断。

## 术语说明

| 术语 | 含义 |
| --- | --- |
| IPC | Inter-Process Communication，进程间通信 |
| ACL | Access Control List，访问控制列表 |
| dylib | macOS 动态库 |
| DYLD | macOS 动态链接器 dyld 相关环境变量的前缀 |
| ECDSA P-256 | 椭圆曲线数字签名算法，256 位曲线 |
| 证书固定 | Certificate pinning，除标准证书验证外，限制可接受的证书或公钥 |
| minisign | 一种基于 Ed25519 的文件签名格式 |

## 1. 目标概况

| 项 | 值 |
| --- | --- |
| Bundle ID | `cn.edu.neusoft.codepass.client` |
| 架构 | 通用二进制（x86_64、arm64） |
| 技术栈 | Tauri v2 / Rust 后端 + 远程 Web 前端（Vite 分包） |
| 前端 | `https://codepass.neusoft.edu.cn/` |
| 接入 | 深信服 aTrust 零信任 VPN + 企业微信扫码 |
| 本地配置 | `~/Library/Application Support/gogo-client/config.json`（644，明文 JSON） |

客户端壳不承载业务逻辑。判题、评分、行为分析都在服务端。壳只承担：请求签名、设备指纹、环境检测、反作弊上报。

## 2. 安全发现

### V-13 · 设备私钥可被同用户进程读取（严重）

| 项 | 内容 |
| --- | --- |
| 位置 | 登录钥匙串，`service = cn.edu.neusoft.codepass.client.device_key`，`account = device-key` |
| 1.3.2 复核 | Keychain 项名未变，二进制中 `-a device-key -s cn.edu.neusoft.codepass.client.device_key` 仍在 |
| 实现方式（本次补证） | 通过外部命令 `/usr/bin/security` 管理，而非 Security.framework；`otool -L` 输出中无 Security.framework |
| 写入参数 | `add-generic-password -U -g`，种子取自 `/dev/urandom` |
| 访问控制 | `kSecAttrAccessible*`、`SecAccessControlCreate*`、`SecKeyCreate*`、`enclave` 命中均为 0 |
| 基线观察 | `security find-generic-password -a device-key -s <service> -w` 返回码 0，无 GUI 授权提示，直接输出 DER PKCS#8 / P-256 私钥 |
| 影响 | 测试中的同用户进程成功读取私钥。私钥泄露可能影响设备身份校验 |
| 本次局限 | **未重新执行读取验证**，仅确认项名与实现路径未变 |
| 关联 | 与 V-17 叠加：私钥可读 + 页面可调用签名，签名能力可被完全外部化 |

### V-02 · 未发现二进制完整性校验（高危）

| 项 | 内容 |
| --- | --- |
| 静态证据 | `SecStaticCodeCheckValidity`、`csops`、`CDHash`/`cdhash`、`SecCodeCopySigningInformation`、`SecRequirementCreateWithString` 命中均为 0；`otool -L` 无 Security.framework |
| 动态证据 | 本轮全部测试均基于「替换 `Contents/Frameworks/anti-detect.dylib` + adhoc 重签名」的客户端，1.3.2 正常启动、正常加载页面、正常提交，未观察到完整性告警或拒绝 |
| 影响 | 修改客户端二进制或替换框架库并重签名后，客户端不阻止运行 |
| 成立条件 | 修改后需重签名（adhoc 即可，无需开发者证书） |
| 局限 | 静态找不到字符串不能证明校验不存在。可能存在：① 以数值常量而非字符串实现的校验；② 仅在特定操作时触发的校验；③ 服务端侧完整性判定。本次只验证了「启动 + 页面加载」路径未被阻止 |

### V-16 · IPC ACL 配置不一致（高危 · 1.3.2 语义变化）

| 项 | 内容 |
| --- | --- |
| 背景 | 页面 JS 中 `window.__TAURI__.core.invoke` 可用 |
| 测试方法 | 从页面上下文调用各命令，按返回的错误类型区分 ACL 拒绝与参数校验失败 |
| **1.3.2 变化** | 基线记录的 `sign_request → not allowed by ACL` **已失效**。1.3.2 中该命令返回 `invalid args 'method'`，即已放行至参数校验阶段，见 V-17 |

ACL 边界实测结果（1.3.2）：

| 命令 | 结果 | 判定 |
| --- | --- | --- |
| `device_id_get` | 返回成功，含设备 ID | ACL 放行 |
| `device_fingerprint` | 返回成功，64 位十六进制 | ACL 放行 |
| `device_fingerprint_sources` | 返回成功，含硬件标识明文 | ACL 放行（新命令） |
| `device_pubkey` | 返回成功，P-256 公钥 | ACL 放行 |
| `device_activate_pubkey` | **空参数即返回 `"ok"`** | ACL 放行，见下 |
| `sign_request` | `invalid args 'method'` | **放行（退化）** |
| `sign_endorsement` | `invalid args 'method'` | ACL 放行 |
| `sign_env_attestation` | `invalid args 'timestamp'` | ACL 放行（新命令） |
| `apply_client_config` | `invalid args 'blockProcesses'` | ACL 放行 |
| `open_client_window` | `invalid args 'url'` | ACL 放行 |
| `sign_set_key` | `invalid args 'key'` | ACL 放行 |

ACL 配置结构：Tauri v2 编译期生成，`__app-acl__` 前缀，15 个自定义命令的 allow/deny 成对各 161/162 条，每条仅被引用一次（对称生成，非差异化策略）。全部 Capability 组装点硬编码 `windows: ["main","sub-*"]` 与 `remote.urls: ["https://codepass.neusoft.edu.cn/*"]` —— 主窗口、任意 `sub-` 前缀子窗口、远程页面在 ACL 上无差别。

**`device_activate_pubkey` 异常点**：传入空对象直接返回 `"ok"`，未要求任何参数。该命令语义应为激活本机设备公钥。**未验证**是否真的改变服务端设备状态（为避免改动账号绑定未重复调用）。

验证局限：上述命令均未传完整参数，未验证能否执行成功及执行效果。`sign_env_attestation` 的参数格式经多轮尝试仍未满足，未取得其签名输出。

### V-17 · `sign_request` 对页面脚本开放，可签出任意 body 的 ECDSA 签名（高危 · 本轮新增）

| 项 | 内容 |
| --- | --- |
| 位置 | IPC 命令 `sign_request` |
| 测试条件 | 官方客户端正常运行并登录；在 webview 页面上下文注入脚本调用该命令 |
| 1.3.0 基线 | 页面调用返回 `not allowed by ACL` |
| 1.3.2 实测 | 返回 `invalid args 'method'`，补齐参数后成功返回签名 |

实测返回（`method=GET`、`path=/game/submit`、`body=""`、`nonce`、`timestamp`、`deviceId` 取本机设备 ID）：

```json
{"signature":"MEUCIGQfRBnGDjU1IAORZLn9oT9bByex3…<已截断>…L4PIcw=","alg":"ecdsa-p256"}
```

| 项 | 内容 |
| --- | --- |
| 观察结果 | 返回结构合法的 ECDSA P-256 签名（DER 编码后 base64），`alg` 字段自述算法 |
| 签名对象 | 由 JS 传入的 `body` 字符串（前端拦截器中即 axios 载荷的 JSON 序列化结果） |
| 参数结构（实测还原） | `{method, path, body, nonce, timestamp, deviceId}`；`timestamp` 需字符串类型 |
| 影响 | 页面上下文的任意脚本可让客户端用设备私钥对任意 body 签名。若服务端仅依据「设备公钥验签 + 重算 body 哈希」判定请求合法性，则签名能力等同于该设备的请求构造能力 |
| 成立条件 | ① 脚本需在页面上下文执行；② 服务端需仅依据该签名做来源判定 |
| 局限 | **未验证**：服务端是否另有会话票据、时间窗、路径白名单、频次限制等独立校验。本次只签了本地，未提交任何签名请求。`path` 是否参与签名、body 归一化规则在 Rust 侧，未反编译确认 |
| 与基线关系 | 基线 V-16 已记录该命令返回 ACL 拒绝；1.3.2 中同一路径变为放行，属防护退化，故单独立项 |

### V-04 · 进程黑名单依赖外部命令（中危）

| 项 | 内容 |
| --- | --- |
| 机制 | 执行 `/bin/ps -A -o ucomm=` 获取进程名，与名单比对。1.3.2 中该字符串仍只出现 2 次（两架构各一） |
| 本地名单 | 216 项（1.3.0 约 180 项）。新增集中于 AI 编程工具与通讯软件：`claude`、`cursor`、`windsurf`、`copilot`、`trae`/`trae cn`/`trae solo`、`doubao`/`豆包`、`yuanbao`/`腾讯元宝`、`workbuddy`、`wechat`/`weixin`/`wxwork`；IDE 侧加 `positron`、`vscodium`、`nvim`、`goland64` |
| 服务端名单 | 实测 64 条（基线记录 65～69 条，随配置变化） |
| **1.3.2 新观察** | 用探针脚本替换 `/bin/ps` 后，**启动与登录阶段观察不到任何 ps 调用**（探针记录为空），客户端正常驻留五分钟以上。说明该扫描只在答题/提交/心跳等特定动作时触发 |
| 动态证据 | 基线已记录：改 `/bin/ps` 后扫描无法取得进程列表，客户端不报错 |
| 影响 | 进程黑名单检测失效，且客户端不报错 |
| 成立条件 | 需要修改二进制并重签名（依赖 V-02） |
| 局限 | 只验证了「改字符串」一条路径；未验证是否存在不依赖 `/bin/ps` 的补充检测（1.3.2 新增的镜像检测见 V-21，属另一维度）；未在答题流程中验证实际调用时机 |

### V-05 · DYLD 检测可被清除（中危）

| 项 | 内容 |
| --- | --- |
| 机制 | 检查环境变量 `DYLD_INSERT_LIBRARIES`，命中时记录环境异常位 |
| 1.3.2 动态证据 | 注入库在 constructor 中 `unsetenv` 后，客户端 stderr 不出现该告警 |
| 影响 | 注入痕迹不被该项检测捕获（仅限环境变量这一路） |
| 局限 | **1.3.2 新增了独立于环境变量的镜像枚举检测**（见 V-21），本方法不覆盖那一路。基线原提醒的 `_dyld_image_count` 侧检查已被证实存在 |

### V-06 · 环境位掩码改写风险（中危 · 未验证）

| 项 | 内容 |
| --- | --- |
| 机制 | 检测结果以 `u32` 位掩码存放于壳内 bss 区（偏移 `+0xd04`），随上报发出 |
| 已知位 | `0x4` 截屏 / `0x20` 进程黑名单 / `0x40` 环境变量 / `0x100` 失焦 / `0x200` 环境篡改 |
| 1.3.2 状态 | 机制未变，本轮仍未做内存改写验证 |
| 局限 | 本条为静态推断。V-04 和 V-05 记录了对应异常位未置位的情况，不能据此证明内存改写有效 |

### V-07 · 截屏进程监控存在时序竞争（中危 · 静态）

| 项 | 内容 |
| --- | --- |
| 机制 | 调用 `/usr/sbin/screencapture` 抓屏，`/usr/bin/sips` 处理。触发分类：`focus_lost`、`paste`、`multi_open`、`hb_resume`、`mass_replace`、`sample` |
| 1.3.2 补充 | 前端限制每会话最多 15 次，`sample` 每 3 分钟一次；上传 `POST /proctor/shots`，载荷含 JPEG base64（压到 ≤380KB）并在图上烧录水印（用户名 · 时间 · 触发原因） |
| 时序局限 | 截图可能在轮询间隔内完成；窗口隐藏也有延迟。本次未统计成功率 |
| 关联 | 1.3.2 新增了截屏产物内容自检，见 V-22 |

### V-08 · 窗口焦点检测可被 Swizzle 绕过（中危）

| 项 | 内容 |
| --- | --- |
| 机制 | `-[NSWindow resignKeyWindow]` 被调用即视为切屏，计入 `envFlags 0x100` 与前端 `focusLostCount` |
| 1.3.2 实现细节 | 前端还监听原生推入的 `gogo-client-focus-lost` / `gogo-client-focus-back` 自定义事件，并带去抖（60s / 300ms / 500ms 三档） |
| 动态证据 | 将该方法替换为空实现后，切换前台应用未触发失焦记录 |
| 影响 | 切屏行为不被该项检测捕获 |
| 局限 | 只覆盖 `resignKeyWindow` 这一条路径。1.3.2 的 delegate 为 `windowDidResignKey:`，但上游被 no-op 后整条链不触发；若存在窗口层级或 `CGWindowList` 侧交叉验证，本方法不覆盖（未见此类迹象，但未穷举） |

### V-18 · 设备指纹明细对页面脚本开放（中危 · 本轮新增）

| 项 | 内容 |
| --- | --- |
| 命令 | `device_fingerprint_sources`（1.3.2 新增） |
| 实测 | 无参数调用即返回指纹来源明细，片段：`{"volumeSerial":"<VOLUME_UUID>","smbi…` |
| 返回内容 | 磁盘卷序列号、SMBIOS 标识等**原始硬件标识**（非哈希） |
| 对比 `device_fingerprint` | 后者返回 64 位十六进制（应为哈希），前者返回可读原始值 |
| 影响 | 页面脚本可直接取得本机硬件标识明文。与其他渠道（日志、崩溃报告、第三方 SDK）组合可提升设备重识别能力 |
| 1.3.2 相关变化 | 指纹来源新增 `diskutil` 的 `Volume UUID`，官方更新清单自述为「补齐设备多源指纹（卷 UUID + IOPlatformUUID）」 |
| 局限 | 仅观察到前若干字段（探针输出截断），完整字段清单未导出；`device_fingerprint` 的哈希算法与输入构造未验证 |

### V-19 · 配置下发端点无鉴权、请求无签名（中危 · 本轮新增）

| 项 | 内容 |
| --- | --- |
| 端点 | `GET https://codepass.neusoft.edu.cn/api/client/config` |
| 实测 | 不带任何 Cookie / Token / 签名头，返回 `HTTP 200`，761 字节 |
| 返回内容 | `{"version":1,"blockProcesses":[64 项],"minVersion":"1.3.0","requireSignature":"require_answer"}` |
| 前端调用方式 | 裸 `fetch("/api/client/config",{cache:"no-store"})`，**不经过 axios 签名拦截器**，因此无 `X-Signature` / `Authorization` |
| 影响 | ① 任何人都能枚举服务端下发的进程黑名单与版本门禁；② 该请求无签名无鉴权，若链路存在中间人（结合基线 V-03 证书固定未实现），可替换名单内容 |
| 落地位置 | `~/Library/Application Support/gogo-client/config.json`，权限 `-rw-r--r--`（644） |
| 更强的劫持面 | 二进制内含环境变量名 `GOGO_CLIENT_CONFIG_URL`，与默认 URL 相邻。**推断**：设置该变量可把配置源指向任意主机。相比中间人，此路径不需要证书条件 |
| 负向结论 | 实测「本地篡改 config.json 清空黑名单后重启」会被服务端重新下发覆盖，故单纯改本地文件无效 |
| 局限 | 中间人影响链与 `GOGO_CLIENT_CONFIG_URL` 的实际读取方式均为**推断**，未做运行时验证；本地缓存 `gogo-clientconfig.json` 是否校验来源未确认 |

### V-20 · 行为指标全前端计算，签名不覆盖其真实性（低危）

| 项 | 内容 |
| --- | --- |
| 上报字段 | 10 个（基线记录为 7 个）：`focusLostCount`、`editEventCount`、`backspaceCount`、`inputIntervalCv`、`untrustedEventCount`、`orphanInputCount`、`bulkInsertCount`、`restoredCodeUnchanged`、`confidence`、`helpLevel` |
| 计算位置 | 全部由页面 JS 计算并写入提交 body |
| 关键推论 | `sign_request` 签的是 body 本身。签名可证明「这台设备发出了这份 body」，**不能**证明「body 里的计数反映真实行为」——改写前端脚本把计数清零，签名照样一致 |
| 阈值（前端常量） | `bulkInsertCount`：单次插入 > 8 字符；`orphanInputCount`：input 距上次 keydown > 300ms；`inputIntervalCv`：最近 500 个间隔的变异系数，样本 < 5 时返回 null |
| 三链路差异 | 闯关用上述编辑行为学指标；考试与竞赛用 `pasteCount` / `multiOpenCount` / `focusLostCount` |
| 局限 | 服务端是否用独立信号（服务端侧会话时长、判题耗时分布、可见性记录）交叉校验，前端不可见 |

### V-21 · 新增镜像注入检测，判据仅为路径前缀（中危 · 本轮新增）

| 项 | 内容 |
| --- | --- |
| 告警串 | `<[env] 检测到非系统 / 非应用包的已加载镜像：{}`（1.3.0 中不存在） |
| 实现依赖 | 导入 `_dyld_image_count`、`_dyld_get_image_name`、`_dyld_get_image_header`、`_dyld_get_image_vmaddr_slide`。**这四个符号 1.3.0 同样存在**（Rust 标准库 backtrace 用），新增的是用它做判定的代码路径 |
| 白名单判据 | 词表新增 `/usr/lib/`、`/Library/Apple/` 两个前缀（1.3.0 无），另有「应用包内」判据 |
| 实测（包外） | 通过自定义 shim 让进程同时加载包内库与 `/private/tmp/probe-x.dylib`，客户端立即输出 `[env] 检测到非系统 / 非应用包的已加载镜像：/private/tmp/probe-x.dylib` |
| 实测（包内对照） | 仅加载 `Contents/Frameworks/anti-detect.dylib` 时**不产生任何告警**（多次启动验证） |
| 结论 | 判据是**镜像文件路径**，不是签名、不是 CDHash、不是加载方式。把库放进 `.app/Contents/` 之下即可通过 |
| 影响 | 该防护只提高门槛，不阻止注入；1.3.2 的实际防护增量有限 |
| 局限 | 未验证「应用包内」的精确判据边界；未验证该判定结果是否写入 `envFlags` 并随请求上报；未验证对 `dlopen` 动态加载是否同样生效 |

### V-22 · 新增截屏产物自检（中危 · 本轮新增）

| 项 | 内容 |
| --- | --- |
| 判据串 | `⚠️ 图很小（可能是纯桌面壁纸，即自身窗口已被隐藏，或屏幕录制权限没生效）` |
| 含义 | 客户端在 `screencapture` 产出图片后检查内容特征，若判定为「只有壁纸」则推断自身窗口被刻意隐藏或未获得屏幕录制权限 |
| 针对目标 | 正是「检测到截图进程就隐藏窗口」这一绕过手法 |
| 影响 | 隐藏窗口的行为可能从「截图内容异常」这条侧信道被反推 |
| 局限 | **未验证**触发阈值、是否上报、是否与 `capture_shot` 共用同一路径。本轮未做隐藏窗口 + 截图的对照实验 |

## 3. 历史问题

### V-01 · 硬编码工厂私钥（1.1.7 存在，1.3.0 已修复，1.3.2 维持）

| 项 | 内容 |
| --- | --- |
| 影响版本 | ≤ 1.1.7 |
| 现状 | 1.3.2 中 `GOGO_FACTORY_KEY`、`factory_key.b64`、P-256 PKCS#8 DER 均为 0 次命中 |
| 保留原因 | 作为背景记录，说明该类问题在本项目中出现过 |

## 4. 附注：未计入问题清单的观察

### 4.1 证书固定缺失（信息级，沿用基线处理）

客户端 stderr 输出：`证书校验挂钩未安装（不影响启动）: 证书错误拦截未在 macOS 上实现`。1.3.2 未变。

该日志提示证书固定可能未启用，不能据此判断标准证书链验证是否正常。若系统信任攻击者控制的 CA 且无其他防护，请求可能面临中间人观察风险；本次未验证。由于需要额外前提（安装受信任 CA）且未实测，不计入问题清单。

### 4.2 路由守卫完全在客户端（未计入）

30 条路由，`beforeEach` 只读 `localStorage.token` 与 `localStorage.user.role` 决定放行，`/levels` 要求 `admin`/`teacher`。二者均可由页面脚本写入。

未计入理由：守卫只决定「页面渲不渲染」，数据是否下发取决于服务端接口鉴权，静态无法判定；且伪造的 `localStorage.user` 会在 `fetchUserInfo()` 返回后被覆盖，伪造窗口很短。

### 4.3 题目对象落在 sessionStorage 且回填不经复核（未计入）

`sessionStorage["currentQuestion_<gameId>"]` 反序列化后直接作为当前题目对象，可篡改展示字段与 `questionId`。

未计入理由：判题在服务端、提交的是代码字符串，篡改题目对象不改变判题结果；改 `questionId` 后服务端是否拒绝未知。

### 4.4 devtools 探测会阻断提交（防护机制，非问题）

前端每秒探测：`console.log` / `Object.defineProperty` 是否被替换、`gogo-devtools-probe` getter 是否被求值、`debugger` 耗时是否 > 200ms、页面隐藏是否 > 5 秒。判定命中后显示遮罩并**在提交入口直接 return**。

原始引用被冻结在 `window.__gogoNativeRefs__`（`writable:false, configurable:false`），改写任一引用即被判为 devtools。

## 5. 检测机制盘点

### 5.1 环境位掩码（u32，bss `+0xd04`）

| 位 | 含义 |
| --- | --- |
| `0x4` | 屏幕采集异常 |
| `0x20` | 进程黑名单命中 |
| `0x40` | 环境变量被篡改 |
| `0x100` | 失焦 |
| `0x200` | 客户端环境被篡改 |

### 5.2 本地检测与安全机制

| 检测 | 实现 |
| --- | --- |
| 进程黑名单 | `/bin/ps -A -o ucomm=`（本地 216 项 + 服务端下发） |
| 已加载镜像 | `_dyld_*` 枚举 + 路径前缀判据（1.3.2 新增） |
| 虚拟机 | `/usr/sbin/sysctl`（`kern.hv_vmm_present` 等） |
| 截屏 | `/usr/sbin/screencapture` + `/usr/bin/sips`，含产物内容自检（1.3.2 新增） |
| 环境变量 | `DYLD_INSERT_LIBRARIES` |
| 硬件指纹 | `/usr/sbin/ioreg`（IOPlatformUUID）、`/usr/sbin/system_profiler`、`/usr/sbin/diskutil`（卷 UUID，1.3.2 新增） |
| 设备密钥 | 钥匙串 `device_key`，经 `/usr/bin/security` CLI 管理 |
| 证书固定 | `publicKeyHashHex`（macOS 未启用） |
| 更新校验 | minisign（内嵌公钥，`minisign-verify 0.2.5`） |

### 5.3 请求签名机制

```
body → SHA256 → bodyHashHex
壳：sign_request(method, path, body, nonce, timestamp, deviceId) → 设备私钥签名
服务端：重算 body 哈希比对，再验签
```

1.3.2 实测确认：算法为 `ecdsa-p256`（另有 `hmac-sha256` 分支在二进制内）；`sign_env_attestation` 校验 `timestamp` + `nonce`（防重放设计）。

签名输入的确切拼接方式（`path` 是否参与、body 如何归一化）未反编译确认。

### 5.4 IPC 命令清单（15 个）

`apply_client_config`、`capture_shot`、`close_client_window`、`device_activate_pubkey`、`device_fingerprint`、`device_fingerprint_sources`（1.3.2 新）、`device_id_get`、`device_id_set`、`device_pubkey`、`install_update`、`open_client_window`、`sign_endorsement`、`sign_env_attestation`（1.3.2 新）、`sign_request`、`sign_set_key`

前端另有 `set_proctor_mode`、`exit_client` 两个命令。

### 5.5 更新机制

```
端点：https://codepass.neusoft.edu.cn/client/mac/latest-mac.json
产物：EduCodePass.app.tar.gz，经 /usr/bin/tar -C 解开，/usr/bin/open 重启
校验：minisign，公钥 base64 长 152 字节（注释含 "minisign public key: D1A338E04F8B5810"）
```

验证函数返回值检查为 `cmn x0,#0x1` / `b.eq <成功路径>`，**失败即阻断**；对应错误串包含 `安装包签名校验失败（文件可能被篡改）`、`The signature verification failed`、`Invalid encoding in minisign data`、`The signature was created with a different key…`。未发现「跳过验证直接解包」的分支。

二进制中存在 `APP_URL 不是合法 URL` 与 `--dump-env`、`--capture-test` 等隐藏开关，说明下载源可由外部覆盖（取值路径未确认，**推断**为环境变量 `APP_URL`）。覆盖下载源不等于绕过签名——仍需持有对应私钥签名才能通过校验。

## 6. 版本差异（1.3.0 → 1.3.2）

官方更新清单自述：`1.3.2：补齐设备多源指纹（卷 UUID + IOPlatformUUID），与 Windows 1.3.3 对齐；安装 dmg 覆盖即可`。

| 维度 | 1.3.0 | 1.3.2 |
| --- | --- | --- |
| 主二进制 | 13,999,632 | 14,049,600（+49,968） |
| 新增 IPC 命令 | — | `device_fingerprint_sources`、`sign_env_attestation` |
| 指纹来源 | `ioreg`、`system_profiler` | 增加 `diskutil` 的 `Volume UUID` |
| 进程黑名单（本地） | 约 180 项，无 AI 工具 | 216 项，新增 AI 与通讯工具（见 V-04） |
| 服务端名单条数 | 65～69 | 64（本轮实测） |
| `sign_request` ACL | 拒绝 | **放行**（V-17） |
| 已加载镜像检测 | 无 | **新增**（V-21） |
| 截屏产物自检 | 未发现 | **新增判据串**（V-22） |
| ACL 结构 | 15 命令 | 15 命令 + 2 新命令，allow/deny 各 161/162 条成对生成 |
| 自校验 | 未发现 | 仍未发现 |
| 工厂私钥 | 已移除 | 仍已移除 |

两版中文串集合差为 2 条：镜像检测告警与「时间戳或 nonce 格式不合法」。1.3.0 独有中文串为空集。

## 7. 披露说明

- 所有验证在本机进行，未对生产服务端发起攻击性测试；`/api/client/config` 为公开只读端点，仅做了一次 `GET`。
- 对敏感 IPC 命令的探测一律只传空参数、止步于参数校验阶段；`device_id_set`、`capture_shot`、`install_update`、`close_client_window` 未调用。
- 报告已脱敏：设备 ID、卷序列号、公钥、签名值虽为实测输出，但均为本机测试环境产物。
- 本报告不含完整利用代码，不提供修复建议。
- 每个结论标注了验证方式。静态分析与推断已显式区分，不能当作「机制不存在」的证明。

1.3.0 基线报告日期：2026-10-16。1.3.2 复核日期：2026-10-23。
