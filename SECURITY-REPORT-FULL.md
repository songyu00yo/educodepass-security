# EduCodePass 客户端安全评估 · 完整技术报告（含绕过实现）

> 目标：EduCodePass（东软信息学院「码途」C/C++ 闯关练习客户端）macOS 版
> 版本：1.3.0（universal: x86_64 + arm64）
> 样本 SHA-256：`5a3a07ebae2df12f4ea9676f9675e8547413369f3059c7bae6e27b5341d07b5d`
> 测试环境：macOS 27.2（26B5112a），arm64，Apple M1 Pro
> 性质：授权范围内的安全评估
> 说明：文中已脱敏。每个结论标注验证方式，静态推断均注明局限。

**统计口径**：本报告记录 **8 项当前版本存在的问题**，另附 **1 项历史问题**（V-01，1.3.0 已修复）。

---

## 目录

1. [目标概况](#1-目标概况)
2. [威胁模型](#2-威胁模型)
3. [完整绕过链（总览）](#3-完整绕过链总览)
4. [逐项绕过实现](#4-逐项绕过实现)
5. [完整工具链代码](#5-完整工具链代码)
6. [实现要点](#6-实现要点)
8. [披露声明](#8-披露声明)

---

## 1. 目标概况

| 项 | 值 |
|---|---|
| Bundle ID | `cn.edu.neusoft.codepass.client` |
| 版本 | 1.3.0 |
| 架构 | universal（x86_64 + arm64） |
| 签名 | adhoc + hardened runtime（`flags=0x10002`），**无 Team ID** |
| 技术栈 | Tauri v2 / Rust 后端 + 远程 Web 前端 |
| 前端 | `https://codepass.neusoft.edu.cn/` |
| 接入 | 深信服 aTrust 零信任 VPN + 企业微信扫码 |
| 主二进制 | `educodepass`（约 13,999,632 字节） |

**架构特点**：客户端壳不承载业务逻辑。题目、评测、评分、行为分析都在远程前端和服务端。壳只做四件事：请求签名、设备指纹、环境检测、反作弊上报。

**Fat 切片**（基址/文件偏移）：

| 架构 | 文件偏移 |
|---|---|
| x86_64 | `0x4000` |
| arm64 | `0x6d8000` |

---

## 2. 威胁模型

攻击者假设：**能登录考试系统的普通学生账号**，对目标主机有本地用户权限，能读写应用目录。

不在范围内：服务端入侵、网络层攻击、物理接触。

**评估目标**：验证客户端本地反作弊检测的**有效性**（即：能否在不被客户端检测的情况下观察/干预评分流程）。

---

## 3. 完整绕过链（总览）

```
① 复制原版 App → 改名（保住原版）
② 主二进制改名 educodepass → educodepass.real
③ 放入自定义 shim 作为新主二进制（负责注入）
④ 编译注入用的 dylib（内含全部绕过逻辑）
⑤ patch 二进制内的 /bin/ps 字符串 → /bin/pX
⑥ adhoc 重签名（必须显式指定 identifier + runtime）
⑦ 启动 → shim 注入 dylib → exec 真二进制
⑧ dylib constructor 清 DYLD 痕迹 → 检测全部失效
```

**一句话总结**：**因为客户端不校验自身二进制完整性（V-02），后续所有本地检测都可以被消音。**

---

## 4. 逐项绕过实现

### 4.1 V-02 二进制完整性 → 基础绕过后门

**为什么可行**：二进制里找不到 `CDHash`、`integrity`、`tamper`、`codesign`、`_CodeSignature` 这些字符串。出现次数都是 0。说明客户端从不校验自己。

**实现步骤**：

```bash
# 1. 复制原版（保留未修改副本）
cp -R /Applications/EduCodePass.app ./EduCodePass-clean.app

# 2. 主二进制改名
cd EduCodePass-clean.app/Contents/MacOS
mv educodepass educodepass.real

# 3. 放入 shim（编译产物）
cp /tmp/shim ./educodepass

# 4. 放入 dylib
mkdir -p ../Frameworks
cp /tmp/anti-detect.dylib ../Frameworks/

# 5. 重签名（见 §5.3，必须显式指定 identifier）
```

---

### 4.2 V-04 进程黑名单 → patch `/bin/ps`

**原理**：客户端执行 `/bin/ps -A -o ucomm=` 获取进程名列表，与本地名单（204 项）+ 服务端动态下发名单（实测 65 条）比对。把二进制里的字符串 `/bin/ps` 改成不存在的路径，`exec` 就会失败，扫描永远返回空。

**patch 点（实测文件偏移）**：

| 架构 | 偏移 | 说明 |
|---|---|---|
| x86_64 | `0x5920d8` | 字符串 `/bin/ps\0` |
| arm64 | `0xbcd530` | **codesign 后实际落到 `0xbc9530`** |

**实现**：

```python
# 把 "/bin/ps" → "/bin/pX"（只改 1 字节，长度不变，无需调整结构）
def patch_ps(path):
    data = bytearray(open(path, 'rb').read())
    needle = b'/bin/ps'
    count = 0
    idx = 0
    while True:
        i = data.find(needle, idx)
        if i < 0:
            break
        data[i + 6] = ord('X')   # 's' → 'X'
        count += 1
        idx = i + 1
    open(path, 'wb').write(data)
    return count
```

**验证**：

```bash
grep -a -c "/bin/pX" EduCodePass-clean.app/Contents/MacOS/educodepass.real
```

> ⚠️ **不要死记 offset**：codesign 会改变 arm64 的实际落点，务必用 `grep -a` 验证。

**效果**：启动日志不再出现 `已提示被限制的程序`，`envFlags 0x20` 永不置位。

---

### 4.3 V-05 DYLD 检测 → `unsetenv`

**原理**：客户端检查环境变量 `DYLD_INSERT_LIBRARIES`，命中时记 `环境变量被篡改` 位并清除。

**绕过**：注入的 dylib 在 **constructor**（最早执行点）里把环境变量抹掉，客户端后续读到的就是空值。

```objc
__attribute__((constructor))
static void init_hook(void) {
    // 必须最先执行：客户端检测时读到空值
    unsetenv("DYLD_INSERT_LIBRARIES");
    unsetenv("DYLD_FORCE_FLAT_NAMESPACE");
    unsetenv("DYLD_LIBRARY_PATH");
}
```

**效果**：stderr 不再出现 `检测到 DYLD_INSERT_LIBRARIES=...`，`envFlags 0x40` 永不置位。

---

### 4.4 V-06 envFlags 位掩码 → 无需处理

**原理**：检测结果以 `u32` 记录在 bss 区偏移 `+0xd04`。

**已知位**：

| 位 | 含义 |
|---|---|
| `0x4` | 屏幕采集（截屏）异常 |
| `0x20` | 进程黑名单命中 |
| `0x40` | 环境变量被篡改 |
| `0x100` | 失焦（切屏） |
| `0x200` | 客户端环境被篡改 |

**说明**：§4.2 和 §4.3 已让对应位不置位，不需要额外改内存。改内存最容易被交叉校验抓到。

---

### 4.5 V-07 截屏监考 → 进程名监控

**原理**：客户端调用 `/usr/sbin/screencapture` 抓屏（**外部进程**），触发分类：

```
focus_lost / paste / multi_open / hb_resume / mass_replace / sample
```

**绕过**：监控 `screencapture` 进程是否出现，出现即隐藏作弊窗口，等它退出再恢复。

```swift
// 用 libproc 直接读进程表（不 spawn 子进程，零痕迹）
func screencaptureRunning() -> Bool {
    let maxPids = 4096
    var pids = [pid_t](repeating: 0, count: maxPids)
    let bytes = proc_listpids(1, 0, &pids, Int32(maxPids * MemoryLayout<pid_t>.size))
    let n = Int(bytes) / MemoryLayout<pid_t>.size
    for i in 0..<n {
        let pid = pids[i]
        if pid <= 0 { continue }
        var buf = [CChar](repeating: 0, count: 128)
        if proc_name(pid, &buf, 128) > 0 {
            if String(cString: buf) == "screencapture" { return true }
        }
    }
    return false
}

// 0.1 秒轮询
Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { _ in
    if screencaptureRunning() { window.orderOut(nil) }
    else { window.orderFrontRegardless() }
}
```

**为什么有效**：抓屏是**子进程**，进程名可被监控；窗口在抓屏前就已从屏幕上消失。


---

### 4.6 V-08 窗口焦点检测 → swizzle `resignKeyWindow`

**原理**：`-[NSWindow resignKeyWindow]` 被调用即视为"切屏"，计入 `envFlags 0x100` + 前端 `focusLostCount`。

**绕过**：把该方法替换为 no-op，窗口永不 resignKey。

```objc
static void void_noop(id self, SEL cmd) { /* 什么都不做 */ }

__attribute__((constructor))
static void init_hook(void) {
    Class W = NSClassFromString(@"NSWindow");
    SEL s = NSSelectorFromString(@"resignKeyWindow");
    Method m = class_getInstanceMethod(W, s);
    if (m) method_setImplementation(m, (IMP)void_noop);
}
```

**补充**：前端 `blur` / `focus` 事件也要拦（JS 层），见 §5.2 的 `kShield` 脚本。

---

### 4.7 V-13 设备私钥读取（**严重 · 未修复**）

**这是本次评估中除 V-01 外最严重的问题。**

#### 现象

一条命令，无需任何高权限，直接读出设备私钥：

```bash
security find-generic-password \
  -a device-key \
  -s cn.edu.neusoft.codepass.client.device_key \
  -w
```

返回码 `0`，输出 base64 编码的 DER PKCS#8 私钥（约 184 字符）：

```
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0w...   ← 已截断
```

#### 格式验证

```bash
security find-generic-password -a device-key \
  -s cn.edu.neusoft.codepass.client.device_key -w \
  | base64 -d | openssl asn1parse -inform DER
```

输出：

```
SEQUENCE
  INTEGER 0
  SEQUENCE
    OBJECT :id-ecPublicKey
    OBJECT :prime256v1            ← P-256 曲线
  OCTET STRING [HEX DUMP]: 306B0201010420...   ← 私钥本体
```

进一步派生公钥，证明是**可用私钥**：

```bash
security find-generic-password -a device-key \
  -s cn.edu.neusoft.codepass.client.device_key -w \
  | base64 -d | openssl pkey -inform DER -pubout
```

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZQredXRgD1f0iNsCBFe0No9y...   ← 已截断
-----END PUBLIC KEY-----
```

#### 为什么能读

客户端用如下命令创建 Keychain 项：

```
/usr/bin/security add-generic-password -U \
  -a device-key \
  -s cn.edu.neusoft.codepass.client.device_key \
  -w <随机生成的私钥>
```

**未设置任何 `SecAccessControl`**（`find-generic-password` 输出中无 ACL 段），因此该项对当前登录用户的所有进程可读。

#### 完整影响链

```
读取 device_key（P-256 私钥）
        ↓
对任意 body 计算 SHA256 → bodyHashHex
        ↓
用该私钥签名（ECDSA P-256）
        ↓
调用同格式请求 → 服务端用对应公钥验签通过
        ↓
以该设备身份发送任意请求（提交答案、读取数据、绕过设备级限制）
```

**本质**：设备身份 = 私钥。私钥可读 = 设备身份可被任意本地程序冒用。


---


### 4.8 V-16 IPC ACL 配置不一致

**背景**：页面 JS 里 `window.__TAURI__.core.invoke` 可用。

探测方式：

```js
var T = window.__TAURI__;
// 返回 12 个模块：
// app|core|dpi|event|image|menu|mocks|path|tray|webview|webviewWindow|window
```

#### 怎么区分「ACL 拒绝」和「参数缺失」

Tauri v2 的执行顺序是先检查 ACL，再做参数反序列化。所以两种错误可以分开：

| 错误类型 | 含义 |
|---|---|
| `not allowed by ACL` | 权限拒绝，命令未被授权 |
| `invalid args xxx` | 权限已通过，只是参数不匹配 |

#### 测试结果

从页面上下文调用，参数传空对象 `{}`：

| 命令 | 返回 | 判定 |
|---|---|---|
| `device_id_get` | 返回成功 | ACL 放行 |
| `device_fingerprint` | 返回成功 | ACL 放行 |
| `device_pubkey` | 返回成功 | ACL 放行 |
| `sign_request` | `not allowed by ACL` | **拒绝** |
| `sign_endorsement` | `invalid args method` | ACL 放行，缺 method |
| `apply_client_config` | `invalid args blockProcesses` | ACL 放行，缺 blockProcesses |
| `open_client_window` | `invalid args url` | ACL 放行，缺 url |
| `sign_set_key` | `invalid args key` | ACL 放行，缺 key |

#### 结论

`sign_request` 被正确限制，页面无法借用客户端签名能力。

但 `sign_set_key`（替换签名密钥）没有被限制。这两个命令的敏感程度同级，权限配置却不同。

#### 未验证的部分

`sign_set_key`、`open_client_window`、`apply_client_config` 只验证到「权限放行 + 参数校验失败」这一步。

没有传入完整参数实际执行，原因：

- `sign_set_key` 会替换设备密钥，可能破坏当前设备登记
- `open_client_window` 会触发 `multi_open`，这是截图触发分类之一
- `apply_client_config` 之前验证过改配置不影响检测

所以「能否调用」是证明的，「调用后产生什么效果」没有验证。


---

### 4.9 逆向补充：完整攻击面清单

#### IPC 命令面（23 个，含 ACL 配对）

| 命令 | ACL |
|---|---|
| `apply_client_config` | allow / deny |
| `capture_shot` | allow / deny |
| `close_client_window` | allow / deny |
| `device_activate_pubkey` | allow / deny |
| `device_fingerprint` | allow / deny |
| `device_id_get` / `device_id_set` | allow / deny |
| `device_pubkey` | allow / deny |
| `install_update` | allow |
| `open_client_window` | allow |
| `sign_request` | allow |
| `sign_endorsement` | allow |
| `sign_set_key` | allow |

#### Tauri IPC 安全机制（**正常，非漏洞**）

```
Tauri-Invoke-Key header     ← invoke key 校验
Origin header               ← 来源校验
missing Tauri-Invoke-Key header  ← 缺失即拒绝
missing Origin header
IpcBlocked
```

#### 更新机制（**校验完整，非漏洞**）

```
端点: https://codepass.neusoft.edu.cn/client/mac/latest-mac.json
校验: minisign（内嵌公钥，注释: "minisign public key: D1A338E04F8B5810"）
错误处理完整:
  · Invalid encoding in minisign data
  · The signature verification failed
  · Unexpected signature algorithm
  · The signature was created with a different key than the one provided
```

#### 设备指纹采集链（外部命令，可 patch）

```
/usr/sbin/ioreg -c IOPlatformExpertDevice        → IOPlatformUUID
/usr/sbin/system_profiler SPHardwareDataType     → Hardware UUID
/usr/bin/security find-generic-password          → device_key（见 V-13）
```

> 这三条与 `/bin/ps` 同性质：**都依赖外部命令**，patch 二进制内路径即可使采集失败。可作为 V-04 的同类问题记录。


---

## 5. 完整工具链代码

### 5.1 shim.c（启动桩）

```c
// shim.c —— 编译后作为新的主二进制，注入 dylib 后 exec 真二进制
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <mach-o/dyld.h>

int main(int argc, char *argv[]) {
    char self[PATH_MAX];
    uint32_t size = sizeof(self);
    if (_NSGetExecutablePath(self, &size) != 0) return 1;

    // self 形如 .../Contents/MacOS/educodepass
    // 真二进制是 .../Contents/MacOS/educodepass.real
    char real[PATH_MAX];
    snprintf(real, sizeof(real), "%s.real", self);

    // dylib 路径：.../Contents/Frameworks/anti-detect.dylib
    char dylib[PATH_MAX];
    char *slash = strrchr(self, '/');           // 最后一个 /
    if (!slash) return 1;
    *slash = '\0';                               // 现在 self = .../Contents/MacOS
    snprintf(dylib, sizeof(dylib), "%s/../Frameworks/anti-detect.dylib", self);

    setenv("DYLD_INSERT_LIBRARIES", dylib, 1);
    // hardened runtime 下还需这两个 entitlement（见 §5.3）
    execv(real, argv);
    perror("execv failed");
    return 1;
}
```

**编译**：

```bash
clang -O2 -arch arm64 -arch x86_64 -o shim shim.c
```

> 注意：shim 是 universal，**不要 strip**，否则签名会变。

---

### 5.2 anti-detect-v4.m（注入 dylib）

```objc
// anti-detect-v4.m —— 反检测 + 读页面 + 编辑器读取
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <libproc.h>

// ============ ① 环境清理（必须最先执行）============
__attribute__((constructor))
static void clean_env(void) {
    unsetenv("DYLD_INSERT_LIBRARIES");
    unsetenv("DYLD_FORCE_FLAT_NAMESPACE");
    unsetenv("DYLD_LIBRARY_PATH");
}

// ============ ② 切屏欺骗 ============
static void void_noop(id self, SEL cmd) { }

__attribute__((constructor))
static void patch_window(void) {
    Class W = NSClassFromString(@"NSWindow");
    Method m = class_getInstanceMethod(W, NSSelectorFromString(@"resignKeyWindow"));
    if (m) method_setImplementation(m, (IMP)void_noop);
}

// ============ ③ 页面读取 + 编辑器读取 ============
@interface Bridge : NSObject <WKScriptMessageHandler, NSURLSessionDelegate>
@end
@implementation Bridge
- (void)userContentController:(WKUserContentController *)ucc
      didReceiveScriptMessage:(WKScriptMessage *)message {
    id body = message.body;
    if (![body isKindOfClass:[NSString class]]) return;
    NSString *text = (NSString *)body;
    if (text.length < 4) return;

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:
        [NSURL URLWithString:@"https://127.0.0.1:8787/hook"]];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 5;
    [req setValue:@"text/plain; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [text dataUsingEncoding:NSUTF8StringEncoding];
    [[self secureSession] dataTaskWithRequest:req].resume;
}

// 信任本地自签证书：必须实现 challenge 回调，delegate:nil 无法通过 TLS 校验
- (void)URLSession:(NSURLSession *)session
    didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
      completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler {
    if ([challenge.protectionSpace.host isEqualToString:@"127.0.0.1"]) {
        completionHandler(NSURLSessionAuthChallengeUseCredential,
                          [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]);
    } else {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}

- (NSURLSession *)secureSession {
    static NSURLSession *s;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        // delegate 必须是 self，否则 challenge 回调不会触发
        s = [NSURLSession sessionWithConfiguration:cfg delegate:self delegateQueue:nil];
    });
    return s;
}
@end

// ============ ④ hook WKWebView 创建，注入 JS ============
static id (*orig_wk_init)(id, SEL, CGRect, WKWebViewConfiguration *);

static const char *kShieldJS =
"(function(){try{"
"if(window.__ok)return;window.__ok=1;"

// 4.1 拦截切屏事件
"function g(o,re){try{if(!o||o.__s)return;o.__s=1;"
"var a=o.addEventListener.bind(o);"
"o.addEventListener=function(t,f,c){if(re.test(String(t)))return;a(t,f,c);};"
"var r=o.removeEventListener.bind(o);"
"o.removeEventListener=function(t,f,c){if(re.test(String(t)))return;r(t,f,c);};"
"}catch(e){}}"
"g(window,/^(blur|focus|gogo-client-focus-lost|gogo-client-focus-back)$/i);"

// 4.2 读页面文本
"function txt(){try{"
"var B={DIV:1,P:1,BR:1,LI:1,TR:1,PRE:1,H1:1,H2:1,H3:1,SECTION:1,ARTICLE:1,LABEL:1,BUTTON:1,OPTION:1,TD:1,TH:1,TABLE:1,UL:1,OL:1,FORM:1};"
"var out='';"
"(function w(n){try{for(var i=0;i<n.childNodes.length;i++){var c=n.childNodes[i];"
"if(c.nodeType===3){out+=c.nodeValue;}"
"else if(c.nodeType===1){var t=c.tagName;"
"if(t==='SCRIPT'||t==='STYLE'||t==='NOSCRIPT')continue;"
"if(t==='BR'){out+='\\n';continue;}"
"var b=B[t];if(b)out+='\\n';"
"if((t==='TEXTAREA'||t==='INPUT')&&typeof c.value==='string'&&c.value.length>2){out+=' '+c.value+' ';}"
"w(c);if(c.shadowRoot)w(c.shadowRoot);if(b)out+='\\n';}}}catch(e){}})(document.body);"
"return out.replace(/[ \\t]+/g,' ').replace(/\\n{3,}/g,'\\n\\n').trim();"
"}catch(e){return (document.body&&document.body.innerText)||'';}}"

// 4.3 读编辑器原文（多引擎探测，保留缩进）
"function editorText(){try{"
"var cm=document.querySelector('.CodeMirror');"
"if(cm&&cm.CodeMirror&&typeof cm.CodeMirror.getValue==='function')return cm.CodeMirror.getValue();"
"if(window.monaco&&window.monaco.editor){var ms=window.monaco.editor.getModels();if(ms&&ms.length)return ms[0].getValue();}"
"var ta=document.querySelector('textarea');if(ta&&typeof ta.value==='string')return ta.value;"
"var c=document.querySelector('[contenteditable=\"true\"]');if(c&&c.innerText)return c.innerText;"
"return '';"
"}catch(e){return '';}}"

// 4.4 定时上报（页面 + 编辑器原文，用 <##E##> 包裹）
"function up(){try{var t=txt();var ed=editorText();"
"var mh=window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.gogo;"
"if(!mh)return;var p=t;"
"if(ed.length>0){p=t+'<##E##>'+ed+'<##/E##>';}"
"if(p.length>2&&p!==window.__last){window.__last=p;mh.postMessage(p.slice(0,300000));}"
"}catch(e){}}"
"if(!window.__pump){window.__pump=1;window.__last='';setInterval(up,500);}"
"}catch(e){}})()";

static id new_wk_init(id self, SEL cmd, CGRect frame, WKWebViewConfiguration *config) {
    // 必须在 init 之前注入：configuration 在 init 时会被复制
    if (config) {
        WKUserContentController *ucc = config.userContentController;
        if (!ucc) { ucc = [WKUserContentController new]; config.userContentController = ucc; }
        @try {
            [ucc addScriptMessageHandler:(id)[Bridge new] name:@"gogo"];
        } @catch (NSException *e) { }
    }
    id wv = orig_wk_init(self, cmd, frame, config);

    // 常驻注入（WKUserScript 会被 wry 干扰）
    __weak WKWebView *weakW = (WKWebView *)wv;
    __block void (^pump)(void) = ^{
        WKWebView *sw = weakW;
        if (!sw) return;
        [sw evaluateJavaScript:[NSString stringWithUTF8String:kShieldJS] completionHandler:nil];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2ull * NSEC_PER_SEC),
                       dispatch_get_main_queue(), ^{ pump(); });
    };
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 500ull * NSEC_PER_MSEC),
                   dispatch_get_main_queue(), ^{ pump(); });
    return wv;
}

__attribute__((constructor))
static void patch_webkit(void) {
    Method m = class_getInstanceMethod(NSClassFromString(@"WKWebView"),
                                       @selector(initWithFrame:configuration:));
    if (m) {
        orig_wk_init = (void *)method_getImplementation(m);
        method_setImplementation(m, (IMP)new_wk_init);
    }
}
```

**编译**：

```bash
clang -dynamiclib -fobjc-arc -arch arm64 -arch x86_64 \
  -framework AppKit -framework Foundation -framework WebKit \
  -o anti-detect.dylib anti-detect-v4.m
```

---

### 5.3 assemble2.py（组装 + 签名）

**这是整个方案最容易翻车的一步**。三个必须显式处理的点：

```python
#!/usr/bin/env python3
import os, shutil, subprocess, sys

SRC = "/Applications/EduCodePass.app"
DST = "./EduCodePass-clean.app"
BID = "cn.edu.neusoft.codepass.client"     # ← 必须显式指定
ENT = "ent.plist"

def run(*a):
    print("  +", " ".join(a))
    subprocess.run(a, check=True)

# 1) 复制
if os.path.exists(DST): shutil.rmtree(DST)
shutil.copytree(SRC, DST, symlinks=True)

mac = os.path.join(DST, "Contents/MacOS")
fw  = os.path.join(DST, "Contents/Frameworks")
os.makedirs(fw, exist_ok=True)

# 2) 主二进制改名 + 放 shim + dylib
real = os.path.join(mac, "educodepass.real")
os.rename(os.path.join(mac, "educodepass"), real)

# 3) patch /bin/ps → /bin/pX（两个架构各一处，用 grep 验证而非死磕 offset）
data = bytearray(open(real, "rb").read())
n = 0
idx = 0
while True:
    i = data.find(b"/bin/ps", idx)
    if i < 0: break
    data[i + 6] = ord("X")
    n += 1
    idx = i + 1
open(real, "wb").write(data)
print(f"  patched {n} 处 /bin/ps -> /bin/pX")

shutil.copy("/tmp/shim", os.path.join(mac, "educodepass"))
shutil.copy("/tmp/anti-detect.dylib", os.path.join(fw, "anti-detect.dylib"))

# 4) 逐组件签名 —— identifier 必须显式指定！
#    ⚠️ 若让 codesign 自动生成 identifier（如 educodepass-<hash>），
#       Keychain 访问会异常 → 请求签名取不到设备私钥 → 服务端报「签名不匹配」
run("codesign", "--force", "--sign", "-", os.path.join(fw, "anti-detect.dylib"))
run("codesign", "--force", "--sign", "-",
    "--identifier", BID, "--options", "runtime",
    "--entitlements", ENT, real)
run("codesign", "--force", "--sign", "-",
    "--identifier", BID, "--options", "runtime",
    "--entitlements", ENT, os.path.join(mac, "educodepass"))
# 最后签 bundle：⚠️ 不能带 --deep（--deep 会递归重签并覆盖上面指定的 identifier）
run("codesign", "--force", "--sign", "-",
    "--identifier", BID, "--options", "runtime",
    "--entitlements", ENT, DST)

print("[+] done")
```

**ent.plist**（hardened runtime 下允许注入所必需）：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
    <key>com.apple.security.cs.disable-library-validation</key><true/>
</dict>
</plist>
```

---

### 5.4 relay.py（本地中转，HTTPS）

**为什么用 Python 不用 Node**：`node` 在客户端的进程黑名单里。

```python
#!/usr/bin/env python3
# 本地中转：收页面/编辑器文本，供外部读取
import http.server, ssl, threading, time, os

LATEST = ""
LOCK = threading.Lock()

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/hook":
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n).decode("utf-8", "replace")
            if len(body) > 3:
                global LATEST
                with LOCK: LATEST = body[:300000]
            self.send_response(204); self.end_headers()
        else:
            self.send_response(404); self.end_headers()

    def do_GET(self):
        if self.path == "/text":
            with LOCK: data = LATEST.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404); self.end_headers()

    def log_message(self, *a): pass   # 零日志

open("/tmp/relay.pid", "w").write(str(os.getpid()))

httpd = http.server.HTTPServer(("127.0.0.1", 8787), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("relay.crt", "relay.key")
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
```

**自签证书**：

```bash
openssl req -x509 -newkey rsa:2048 -keyout relay.key -out relay.crt \
  -days 3650 -nodes -subj "/CN=127.0.0.1"
```

---

### 5.5 浮窗输入（CGEvent）

**核心**：用 CGEvent 模拟键盘，绕开剪贴板禁用；`isTrusted=true`（不像 JS 合成事件）。

```swift
final class Typer {
    // ⚠️ 必须用 privateState：不继承系统修饰键状态
    private static let src = CGEventSource(stateID: .privateState)

    // US 键盘虚拟键码映射（macOS kVK_* 常量）
    private static let map: [Character: (CGKeyCode, Bool)] = [
        // 小写字母
        "a":(0,false),"s":(1,false),"d":(2,false),"f":(3,false),"h":(4,false),
        "g":(5,false),"z":(6,false),"x":(7,false),"c":(8,false),"v":(9,false),
        "b":(11,false),"q":(12,false),"w":(13,false),"e":(14,false),"r":(15,false),
        "y":(16,false),"t":(17,false),"o":(31,false),"u":(32,false),"i":(34,false),
        "p":(35,false),"l":(37,false),"j":(38,false),"k":(40,false),
        "n":(45,false),"m":(46,false),
        // 大写字母（需 Shift）
        "A":(0,true),"S":(1,true),"D":(2,true),"F":(3,true),"H":(4,true),
        "G":(5,true),"Z":(6,true),"X":(7,true),"C":(8,true),"V":(9,true),
        "B":(11,true),"Q":(12,true),"W":(13,true),"E":(14,true),"R":(15,true),
        "Y":(16,true),"T":(17,true),"O":(31,true),"U":(32,true),"I":(34,true),
        "P":(35,true),"L":(37,true),"J":(38,true),"K":(40,true),
        "N":(45,true),"M":(46,true),
        // 数字
        "1":(18,false),"2":(19,false),"3":(20,false),"4":(21,false),"5":(23,false),
        "6":(22,false),"7":(26,false),"8":(28,false),"9":(25,false),"0":(29,false),
        // 符号（无需 Shift）
        "-":(27,false),"=":(24,false),"[" :(33,false),"]":(30,false),
        "\\":(42,false),";":(41,false),"'":(39,false),",":(43,false),
        ".":(47,false),"/":(44,false),"`":(50,false),
        // 符号（需 Shift）
        "!":(18,true),"@":(19,true),"#":(20,true),"$":(21,true),"%":(23,true),
        "^":(22,true),"&":(26,true),"*":(28,true),"(":(25,true),")":(29,true),
        "_":(27,true),"+":(24,true),"{":(33,true),"}":(30,true),
        "|":(42,true),":":(41,true),"\"":(39,true),"<":(43,true),
        ">":(47,true),"?":(44,true),"~":(50,true),
        // 控制字符
        " ":(49,false), "\n":(36,false), "\t":(48,false),
    ]

    static func postKey(_ code: CGKeyCode, _ shift: Bool) {
        let f: CGEventFlags = shift ? .maskShift : []
        if let d = CGEvent(keyboardEventSource: src, virtualKey: code, keyDown: true) {
            d.flags = f
            d.post(tap: .cghidEventTap)
        }
        // ★ 关键：keyDown 与 keyUp 之间必须留间隔
        //   发太密系统会丢事件（实测丢过 "oo"、")" 等字符）
        usleep(4000)
        if let p = CGEvent(keyboardEventSource: src, virtualKey: code, keyDown: false) {
            p.flags = f
            p.post(tap: .cghidEventTap)
        }
    }
}
```

---

## 6. 实现要点

这 10 条是做出可用工具必须处理的技术点。每条给出做法。

### 6.1 patch 后验证，不记偏移

`/bin/ps` 的 patch 位置会随签名变化。改完用 `grep -a` 确认：

```bash
grep -a -c "/bin/pX" <binary>   # 应该有匹配
grep -a -c "/bin/ps" <binary>   # 应该为 0
```

### 6.2 签名必须显式指定 identifier

codesign 默认给非标准位置的二进制生成随机 identifier。Keychain 访问绑定 identifier，随机值会导致取不到设备私钥，表现是提交时报签名错误。

指定方式：

```bash
codesign --force --sign - \
  --identifier cn.edu.neusoft.codepass.client \
  --options runtime \
  --entitlements ent.plist educodepass.real
```

签 bundle 时不要加 `--deep`。它会递归重签，覆盖上面指定的 identifier。

### 6.3 组合键改用单键

CGEvent 发组合键时，修饰标志不可靠。需要反缩进时，用三步：

```swift
keyStroke(123, [.maskCommand])   // Cmd+← 到行首
keyStroke(117, [])               // Forward Delete 删空格
keyStroke(124, [.maskCommand])   // Cmd+→ 回行尾
```

### 6.4 WebKit 用 keycode 注入字符

`keyboardSetUnicodeString` 对 WebKit 无效。改用 `virtualKey` 加 keycode：

```swift
if let (code, shift) = map[ch] {
    postKey(code, shift)
}
```

### 6.5 注入前切英文输入法

中文输入法会把 keycode 转成候选字。输入前切到 ABC，输入中定期检查：

```swift
if let cur = currentInputId(), cur != "com.apple.keylayout.ABC" {
    if let en = englishInput() { TISSelectInputSource(en) }
    usleep(350_000)
}
```

每 15 个字符检查一次。

### 6.6 keyDown 与 keyUp 留间隔

两者之间留 4 ms。间隔太短会丢字符。

```swift
usleep(4000)
```

### 6.7 缩进用读回校正

编辑器自动缩进不公开。做法是每行输入后读回实际内容：

1. 从 JS 读编辑器原文。
2. 取当前行的前导空白，算格数。
3. 和目标对比。
4. 少了补 Tab，多了删空格。

读编辑器要覆盖多种引擎：

```js
function editorText(){
  var cm = document.querySelector('.CodeMirror');
  if (cm && cm.CodeMirror) return cm.CodeMirror.getValue();
  if (window.monaco) return window.monaco.editor.getModels()[0].getValue();
  var ta = document.querySelector('textarea');
  if (ta) return ta.value;
  var ce = document.querySelector('[contenteditable="true"]');
  if (ce) return ce.innerText;
  return '';
}
```

读页面文本的函数常带 `replace(/[ \t]+/g,' ')`。编辑器原文要单独读，原样返回。

### 6.8 清理进程用 PID 文件

`pkill -f` 匹配完整命令行，会误杀调用方。启动时写 PID，清理时按 PID kill：

```python
open("/tmp/relay.pid", "w").write(str(os.getpid()))
# 清理
os.kill(int(open("/tmp/relay.pid").read()), signal.SIGTERM)
```

### 6.9 重签名后重置 TCC 授权

TCC 授权绑定 CDHash。重签名后授权失效，用 tccutil 重置：

```bash
tccutil reset Accessibility <bundle-id>
tccutil reset ListenEvent <bundle-id>
```

### 6.10 权限检查只作提示

`AXIsProcessTrusted()` 在部分系统上返回 false，但按键实际可用。用它决定是否弹授权提示，不要做硬性拦截。

## 7. 披露声明

- 本报告用于**授权范围内的安全评估**。
- 所有验证在**本地测试环境**完成，未对生产服务端发起攻击。
- 文中**已脱敏**：用户名、设备登记码、API 密钥、个人标识均已移除。

---

*最后更新：2026-10-16*
