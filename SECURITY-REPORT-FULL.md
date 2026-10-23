# EduCodePass 客户端安全评估：技术报告

[返回项目首页](README.md) · [查看安全发现](SECURITY-REPORT.md)

## 阅读说明

本文补充技术细节，评估对象为 macOS 客户端 **1.3.2**；1.3.0 的验证记录保留在第 4～6 节作为对照基线。[样本与测试环境](SECURITY-REPORT.md#评估信息)见安全报告。

共记录 14 项安全发现：8 项为 1.3.0 基线复核，6 项为 1.3.2 新增。其中 V-06 尚待运行时验证。历史问题 V-01 见[简版报告](SECURITY-REPORT.md#3-历史问题)。严重程度沿用原报告评级。

| 发现 | 验证状态 | 主要边界 |
| --- | --- | --- |
| V-02、V-04、V-05、V-08 | 报告记录了动态观察 | 仅覆盖所述测试路径 |
| V-13 | 读取和格式解析实测（1.3.0）；1.3.2 仅静态确认实现方式 | 服务端操作权限未验证 |
| V-16 | 部分命令成功返回，敏感命令返回参数错误 | 敏感命令执行效果未验证 |
| V-17 | 签名返回值实测 | 服务端校验强度未验证，未提交任何签名请求 |
| V-18、V-19 | 返回内容实测 | 完整字段与缓存信任策略未确认 |
| V-21 | 包内/包外对照实测 | 判据边界与是否上报未验证 |
| V-06、V-07、V-22 | 静态推断 | 内存改写、截图隐藏成功率、自检阈值均未验证 |

第 5 节保留原有验证代码；第 6 节保留实现记录。仓库未附独立编译与运行验收记录，文档整理未验证这些代码。下文的本地观察不代表服务端的最终判定。

## 目录

1. [目标概况](#1-目标概况)
2. [威胁模型](#2-威胁模型)
3. [验证流程概览](#3-验证流程概览)
4. [逐项验证记录](#4-逐项验证记录)
5. [验证代码](#5-验证代码)
6. [实现要点](#6-实现要点)
7. [1.3.2 复核记录](#7-132-复核记录)
8. [披露声明](#8-披露声明)

## 术语说明

| 术语 | 含义 |
| --- | --- |
| IPC | Inter-Process Communication，进程间通信 |
| ACL | Access Control List，访问控制列表 |
| dylib | macOS 动态库 |
| DYLD | macOS 动态链接器 dyld 相关环境变量的前缀 |
| 证书固定 | Certificate pinning，除标准证书验证外，限制可接受的证书或公钥 |
| TCC | Transparency, Consent, and Control，macOS 隐私权限机制 |

## 1. 目标概况

| 项 | 值 |
| --- | --- |
| Bundle ID | `cn.edu.neusoft.codepass.client` |
| 版本 | 1.3.2（对照基线 1.3.0） |
| 架构 | 通用二进制（x86_64、arm64） |
| 签名 | adhoc + hardened runtime（`flags=0x10002`），无 Team ID |
| 技术栈 | Tauri v2 / Rust 后端 + 远程 Web 前端 |
| 前端 | `https://codepass.neusoft.edu.cn/` |
| 接入 | 深信服 aTrust 零信任 VPN + 企业微信扫码 |
| 主二进制 | `educodepass`（1.3.2 为 14,049,600 字节；1.3.0 为 13,999,632） |

架构特点：客户端壳不承载业务逻辑。题目、评测、评分、行为分析都在远程前端和服务端。壳只做四件事：请求签名、设备指纹、环境检测、反作弊上报。

通用二进制的架构切片文件偏移：

| 架构 | 1.3.0 | 1.3.2 |
| --- | --- | --- |
| x86_64 | `0x4000` | `0x4000` |
| arm64 | `0x6d8000` | `0x6e0000` |

注意：1.3.2 的 arm64 切片起点与 1.3.0 不同，且**每次 codesign 重签名后内部偏移都会漂移**。定位字符串应使用字节模式搜索，不要硬编码偏移。

## 2. 威胁模型

攻击者假设：攻击者持有能登录考试系统的普通学生账号，拥有本地用户权限，能读写应用目录。

不在范围内：服务端入侵、网络层攻击、物理接触。

评估目标：检查修改客户端后，本地检测能否识别异常。服务端评分流程与业务权限不在本次验证范围内。

## 3. 验证流程概览

```
① 复制原版 App → 改名（保住原版）
② 主二进制改名 educodepass → educodepass.real
③ 放入自定义 shim 作为新主二进制（负责注入）
④ 准备注入用的 dylib
⑤ patch 二进制内的 /bin/ps 字符串 → /bin/pX
⑥ adhoc 重签名（必须显式指定 identifier + runtime）
⑦ 启动 → shim 注入 dylib → exec 真二进制
⑧ 观察各检测项的日志和异常位，分别记录结果
```

报告记录了修改客户端后部分检测结果发生变化的情况。各项验证边界见第 4 节，不能据此认定所有本地检测失效。

## 4. 逐项验证记录

### 4.1 V-02 二进制完整性

静态观察：相关字符串检索结果均为 0，不能据此证明不存在完整性校验。简版报告另记录了修改后正常启动与提交的情况，结论仅覆盖该测试路径。

实现步骤：

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

### 4.2 V-04 进程黑名单

原理：客户端执行 `/bin/ps -A -o ucomm=` 获取进程名，与本地名单和服务端名单比对。原记录列出本地名单 204 项，服务端名单实测为 65～69 条。

报告记录了修改命令路径后无法取得进程列表的情况，未验证是否存在补充检测。

文件修改位置（原记录中的文件偏移）：

| 架构 | 偏移 | 说明 |
| --- | --- | --- |
| x86_64 | `0x5920d8` | 字符串 `/bin/ps\0` |
| arm64 | `0xbcd530` | codesign 后实际落到 `0xbc9530` |

实现：

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

验证：

```bash
grep -a -c "/bin/pX" EduCodePass-clean.app/Contents/MacOS/educodepass.real
```

> 文件偏移取决于当前样本与签名状态。原记录列出签名前后的不同偏移，不能直接套用于其他样本。

观察结果：在所述测试路径中，启动日志未出现 `已提示被限制的程序`，未观察到 `envFlags 0x20` 置位。

### 4.3 V-05 DYLD 检测 → `unsetenv`

原理：客户端检查环境变量 `DYLD_INSERT_LIBRARIES`，命中时记 `环境变量被篡改` 位并清除。

验证思路：注入代码在初始化函数中清除环境变量。是否影响检测，取决于注入代码与检测逻辑的执行顺序。

```objc
__attribute__((constructor))
static void init_hook(void) {
    // 必须最先执行：客户端检测时读到空值
    unsetenv("DYLD_INSERT_LIBRARIES");
    unsetenv("DYLD_FORCE_FLAT_NAMESPACE");
    unsetenv("DYLD_LIBRARY_PATH");
}
```

观察结果：在所述测试路径中，未观察到对应环境变量告警或 `envFlags 0x40` 置位。该结果只覆盖环境变量检测。

### 4.4 V-06 环境位掩码改写风险（待验证）

原理：检测结果以 `u32` 记录在 bss 区偏移 `+0xd04`。

已知位：

| 位 | 含义 |
| --- | --- |
| `0x4` | 屏幕采集（截屏）异常 |
| `0x20` | 进程黑名单命中 |
| `0x40` | 环境变量被篡改 |
| `0x100` | 失焦（切屏） |
| `0x200` | 客户端环境被篡改 |

验证边界：本次未改写环境位掩码。第 4.2 节和第 4.3 节的观察不能证明内存改写有效，也未验证相关交叉校验。

### 4.5 V-07 截屏进程监控风险（待验证）

原理：客户端调用 `/usr/sbin/screencapture` 抓屏（外部进程），触发分类：

```
focus_lost / paste / multi_open / hb_resume / mass_replace / sample
```

验证思路：观察截图进程与测试窗口状态的时序关系。下方代码为原报告片段，实际效果未验证。

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

验证边界：检测到进程后，截图可能已经完成。轮询间隔、窗口隐藏延迟和截图参数都会影响结果，本次未统计成功率。

### 4.6 V-08 窗口焦点检测

原理：`-[NSWindow resignKeyWindow]` 被调用即视为“切屏”，计入 `envFlags 0x100` + 前端 `focusLostCount`。

观察结果：简版报告记录了替换方法后，切换前台应用未触发失焦记录的情况。该结果只覆盖所述检测路径。

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

补充：前端 `blur` / `focus` 事件也要拦（JS 层），见第 5.2 节的 `kShieldJS` 脚本。

### 4.7 V-13 设备私钥读取

本项沿用原报告的严重评级。测试条件与影响边界见[简版报告](SECURITY-REPORT.md#2-安全发现)。

**（1）现象**

原报告记录：在同一登录会话中，普通用户运行系统工具读取私钥，返回码为 0，未出现图形授权提示。

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

**（2）格式验证**

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

原记录还展示了派生公钥的结果。这说明输出可解析为私钥，尚不能证明服务端接受相关操作。

```bash
security find-generic-password -a device-key \
  -s cn.edu.neusoft.codepass.client.device_key -w \
  | base64 -d | openssl pkey -inform DER -pubout
```

```
-----BEGIN PUBLIC KEY-----
<DEVICE_PUBKEY_PEM 前 32 基址字符…>   ← 已截断
-----END PUBLIC KEY-----
```

**（3）访问控制观察**

客户端用如下命令创建 Keychain 项：

```
/usr/bin/security add-generic-password -U \
  -a device-key \
  -s cn.edu.neusoft.codepass.client.device_key \
  -w <随机生成的私钥>
```

访问控制边界：原记录未见访问控制列表输出，但这不足以证明没有访问控制。读取结果只代表测试进程在当时会话中的访问情况。

**（4）潜在影响与验证边界**

读取私钥 → 解析私钥并派生公钥（报告已记录）

后续风险：私钥可能用于设备签名。服务端接受范围与业务操作效果未验证。

私钥泄露可能影响设备身份校验。登录态、权限和服务端请求校验仍会限制操作范围，本次未验证设备身份冒用的完整过程。

### 4.8 V-16 IPC ACL 配置不一致

背景：页面 JS 里 `window.__TAURI__.core.invoke` 可用。

探测方式：

```js
var T = window.__TAURI__;
// 返回 12 个模块：
// app|core|dpi|event|image|menu|mocks|path|tray|webview|webviewWindow|window
```

**（1）错误类型与判断依据**

原报告依据 Tauri v2 的权限检查和参数校验顺序，区分以下错误。具体顺序仍需结合当前版本实现核对：

| 错误类型 | 含义 |
| --- | --- |
| `not allowed by ACL` | 权限拒绝，命令未被授权 |
| `invalid args xxx` | 已进入参数校验，执行效果未验证 |

**（2）测试结果**

从页面上下文调用，参数传空对象 `{}`：

| 命令 | 返回 | 判定 |
| --- | --- | --- |
| `device_id_get` | 返回成功 | ACL 放行 |
| `device_fingerprint` | 返回成功 | ACL 放行 |
| `device_pubkey` | 返回成功 | ACL 放行 |
| `sign_request` | `not allowed by ACL` | 拒绝 |
| `sign_endorsement` | `invalid args method` | ACL 放行，缺 method |
| `apply_client_config` | `invalid args blockProcesses` | ACL 放行，缺 blockProcesses |
| `open_client_window` | `invalid args url` | ACL 放行，缺 url |
| `sign_set_key` | `invalid args key` | ACL 放行，缺 key |

**（3）结论**

本次页面上下文调用 `sign_request` 返回权限拒绝。

`sign_set_key` 返回参数错误，表现与 `sign_request` 不同。应结合各命令的用途核对授权策略；本次未验证密钥替换效果。

**（4）未验证的部分**

`sign_set_key`、`open_client_window`、`apply_client_config` 只观察到参数校验错误。

原记录未传入完整参数，并列出以下考虑：

- `sign_set_key` 会替换设备密钥，可能破坏当前设备登记。
- `open_client_window` 会触发 `multi_open`，这是截图触发分类之一。
- `apply_client_config` 曾有配置变更的观察记录，但未附完整测试条件。

上述敏感命令只验证到参数校验阶段，尚未验证能否执行成功及执行效果。

### 4.9 其他安全机制观察

**（1）IPC 命令与权限标识**

下表记录静态检出的权限标识，不代表当前页面获得相应授权。运行时结果见第 4.8 节。

| 命令 | 检出的权限标识 |
| --- | --- |
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

**（2）Tauri IPC 校验相关信息**

```
Tauri-Invoke-Key header     ← invoke key 校验
Origin header               ← 来源校验
missing Tauri-Invoke-Key header  ← 缺失即拒绝
missing Origin header
IpcBlocked
```

**（3）更新签名校验相关信息**

```
端点: https://codepass.neusoft.edu.cn/client/mac/latest-mac.json
校验: minisign（内嵌公钥，注释: "minisign public key: D1A338E04F8B5810"）
错误处理完整:
  · Invalid encoding in minisign data
  · The signature verification failed
  · Unexpected signature algorithm
  · The signature was created with a different key than the one provided
```

**（4）设备指纹与密钥读取命令**

```
/usr/sbin/ioreg -c IOPlatformExpertDevice        → IOPlatformUUID
/usr/sbin/system_profiler SPHardwareDataType     → Hardware UUID
/usr/bin/security find-generic-password          → device_key（见 V-13）
```

> 上述功能依赖外部命令。路径修改后的实际行为与失败处理尚未逐项验证。

## 5. 验证代码

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

编译：

```bash
clang -O2 -arch arm64 -arch x86_64 -o shim shim.c
```

> 注意：shim 是 universal，不要 strip，否则签名会变。

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

编译：

```bash
clang -dynamiclib -fobjc-arc -arch arm64 -arch x86_64 \
  -framework AppKit -framework Foundation -framework WebKit \
  -o anti-detect.dylib anti-detect-v4.m
```

### 5.3 assemble2.py（组装 + 签名）

本节保留组装与签名脚本，涉及应用副本、组件签名和签名标识。

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

ent.plist（hardened runtime 下允许注入所必需）：

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

### 5.4 relay.py（本地中转，HTTPS）

原记录使用 Python 编写本地中转程序，并指出 `node` 在进程黑名单中。

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

自签证书：

```bash
openssl req -x509 -newkey rsa:2048 -keyout relay.key -out relay.crt \
  -days 3650 -nodes -subj "/CN=127.0.0.1"
```

### 5.5 浮窗输入（CGEvent）

原记录使用 CGEvent 模拟键盘输入，并将其与 JavaScript 合成事件作比较。事件可信标记与客户端是否接受输入应分别验证。

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

## 6. 实现要点

以下为原测试中的实现记录。结果可能受系统版本、应用签名和编辑器实现影响，尚未作为通用结论验证。

### 6.1 文件偏移与样本状态

原记录中的文件偏移在签名前后不同。以下保留字符串检查示例：

```bash
grep -a -c "/bin/pX" <binary>   # 应该有匹配
grep -a -c "/bin/ps" <binary>   # 应该为 0
```

### 6.2 签名标识与钥匙串访问

原记录将签名标识变化与钥匙串读取失败联系起来，现有材料未单独验证因果关系。钥匙串访问条件还需结合实际访问控制配置判断。

指定方式：

```bash
codesign --force --sign - \
  --identifier cn.edu.neusoft.codepass.client \
  --options runtime \
  --entitlements ent.plist educodepass.real
```

签 bundle 时不要加 `--deep`。它会递归重签，覆盖上面指定的 identifier。

### 6.3 组合键改用单键

原测试记录了组合键输入异常，以下为当时采用的分步输入示例：

```swift
keyStroke(123, [.maskCommand])   // Cmd+← 到行首
keyStroke(117, [])               // Forward Delete 删空格
keyStroke(124, [.maskCommand])   // Cmd+→ 回行尾
```

### 6.4 WebKit 用 keycode 注入字符

原测试未通过 `keyboardSetUnicodeString` 完成目标输入，随后使用了虚拟键码。该观察不能推广到所有 WebKit 场景。

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

原测试记录了重签名后需要重新授权的情况。授权是否保留取决于系统的身份判定，不能仅归因于 CDHash。以下保留原记录中的重置命令：

```bash
tccutil reset Accessibility <bundle-id>
tccutil reset ListenEvent <bundle-id>
```

### 6.10 权限检查与输入结果

原记录称权限检查返回 `false` 时仍观察到按键输入，但未列出对应系统版本与完整条件。权限判断与输入结果应分别记录，不能据此制定通用处理规则。

## 7. 1.3.2 复核记录

本节记录 1.3.2 相对 1.3.0 的复核过程。所有命令与输出均为本机实测，输出中涉及的设备标识已说明为测试环境产物。

### 7.1 复核方式

| 项 | 做法 |
| --- | --- |
| 版本确认 | `/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" .../Info.plist` → `1.3.2`；二进制 14,049,600 字节 |
| 二进制差异 | `lipo -thin` 拆分两架构，`strings -a -n 8` 取集合并求差；中文串单独求差 |
| 前端获取 | `GET https://codepass.neusoft.edu.cn/` → 入口 HTML → 从主 bundle 提取全部 `assets/*.js` 清单（49 个懒加载 chunk + 3 个主 bundle），全部下载后按关键字定位 |
| IPC 探测 | 注入自定义 dylib，在 webview 上下文调用 `window.__TAURI__.core.invoke`，把结果经 `WKScriptMessageHandler` 回传落盘 |
| 镜像检测验证 | 自编译「追加式」shim，让进程同时加载两个库，对比是否告警 |

### 7.2 ACL 探测的判定方法

Tauri v2 的命令调用有两层前置检查：ACL 权限、参数反序列化。二者返回的错误串不同，可据此区分：

- ACL 拒绝：`Command <name> not allowed by ACL`
- 参数缺失：`invalid args <field> for command <name>: command <name> missing required key <field>`

因此**只传空对象 `{}`** 即可判断权限是否放行：返回 `invalid args` 说明已过 ACL。这是在不改变任何服务端状态的前提下取得权限信息的方法。

对敏感命令一律止步于此；`device_id_set`、`capture_shot`、`install_update`、`close_client_window` 未调用。

实测结果见安全报告 V-16 表格。关键差异：`sign_request` 在 1.3.0 返回 ACL 拒绝，在 1.3.2 返回 `invalid args 'method'`。

### 7.3 参数补齐还原签名入参

Rust serde 按字段声明顺序报出第一个缺失项，逐个补齐即可还原完整结构：

| 轮次 | 返回 | 推断出的字段 |
| --- | --- | --- |
| 1 | `missing required key method` | `method` |
| 2 | `missing required key path` | `path` |
| 3 | `missing required key body` | `body` |
| 4 | `invalid type: integer, expected a string`（timestamp） | `timestamp` 为字符串 |
| 5 | 成功 | 完整入参 `{method, path, body, nonce, timestamp, deviceId}` |

最终返回：

```json
{"signature":"MEUCIGQfRBnGDjU1IAORZLn9oT9bByex3…<已截断>…L4PIcw=","alg":"ecdsa-p256"}
```

同一方法用于 `sign_endorsement`（还需 `bodyHashHex`、`publicKeyHashHex`）与 `sign_env_attestation`（需 `timestamp` + `nonce`，且对二者格式有额外校验，未通过）。

### 7.4 已加载镜像检测的验证

1.3.2 新增告警串 `<[env] 检测到非系统 / 非应用包的已加载镜像：{}`，1.3.0 中不存在。

验证步骤与两个关键坑：

| 步骤 | 结果 |
| --- | --- |
| 用 `launchctl setenv DYLD_INSERT_LIBRARIES /tmp/probe-x.dylib` 再 `open` 启动 | **无效**——`shim.c` 中 `setenv(..., 1)` 会覆盖该变量，探针库未加载（`vmmap` 中无该库） |
| 自编译「追加式」shim：把既有值与包内 dylib 用冒号拼接 | 探针库成功加载 |
| 同时加载 `Contents/Frameworks/anti-detect.dylib` 与 `/private/tmp/probe-x.dylib` | 输出 `[env] 检测到非系统 / 非应用包的已加载镜像：/private/tmp/probe-x.dylib` |
| 只加载包内库 | 无任何告警（多次启动验证） |

结论：判据为镜像**路径前缀**，不是签名或 CDHash。1.3.2 因此只提高了注入门槛，未阻止注入。

另注：`_dyld_image_count`、`_dyld_get_image_name`、`_dyld_get_image_header`、`_dyld_get_image_vmaddr_slide` 四个符号在 **1.3.0 中同样存在**（Rust 标准库 backtrace 依赖），因此「符号存在」不能作为「存在该检测」的证据，必须结合告警串与代码路径判断。

### 7.5 必须排除的假信号

用 `nohup ./Contents/MacOS/educodepass &` 直接启动二进制（不经 LaunchServices）时，客户端窗口无法建立（CPU 0%、无页面渲染），并在 10–60 秒内打印：

```
[client] 已提示被限制的程序，按约定退出客户端
```

这与版本、二进制修改、运行环境均无关，纯属启动方式导致的假阳性。若据此判断「检测加强」会得出错误结论。

正确方式：

```bash
open -a "$PWD/EduCodePass-clean.app" --stdout /tmp/o.log --stderr /tmp/e.log
```

同样，运行会触发 TCC 权限弹窗或抢占焦点的诊断工具（例如临时编译的窗口枚举程序）也可能间接干扰客户端。做稳定性对照时应保持环境静默。

### 7.6 配置下发的两个负向结论

| 假设 | 实测 | 结论 |
| --- | --- | --- |
| 改本地 `config.json` 可清空进程黑名单 | 清空后重启，文件被服务端重新下发覆盖回 64 条；`update.log` 记录「应用服务端下发的进程名单：64 条」 | 无效 |
| `/api/client/config` 需要鉴权 | 不带任何凭证 `GET` 返回 `HTTP 200`、761 字节 | 不需要；内容公开 |

### 7.7 前端侧复核要点

前端 52 个 chunk 全量检索后的主要结论：

- 行为指标上报字段为 **10 个**（基线记录为 7 个），全部由页面 JS 计算。
- `inputIntervalCv` 的实现为「最近 500 个按键间隔的变异系数」，样本少于 5 个时返回 `null`。
- `bulkInsertCount` 阈值为单次插入 > 8 字符；`orphanInputCount` 阈值为 input 距上次 keydown > 300ms。
- devtools 探测为四重（引用替换、getter 陷阱、`debugger` 计时、页面隐藏时长），命中后**阻断提交**。
- 鉴权相关的 `requireSignature` 只对浏览器渠道生效；客户端内该标记被跳过。
- 未发现硬编码密钥、Token、内部域名；未发现浏览器环境指纹采集（屏幕、时区、字体、WebGL、音频、canvas）。

## 8. 披露声明

- 本报告用于授权范围内的安全评估。
- 所有验证在本地测试环境完成，未对生产服务端发起攻击。
- 文中已脱敏：用户名、设备登记码、API 密钥、个人标识均已移除。

原报告日期：2026-10-16。文档整理日期：2026-10-20。1.3.2 复核日期：2026-10-23。
