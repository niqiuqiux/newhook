# NewHook — ARM64 Inline Hook 框架设计文档

## 1. 项目概述

NewHook 是一个专为 ARM64 (AArch64) 架构设计的 Android inline hook 库，
基于对 shadowhook 2.0.0 架构的深入分析重新设计实现。

### 1.1 设计目标

| 目标 | 说明 |
|------|------|
| 仅 ARM64 | 不支持 ARM32，代码更精简，无条件编译分支 |
| 双构建模式 | 同时支持编译为动态库 (.so) 和静态库 (.a) |
| 三种 Hook 模式 | UNIQUE（单 hook）、MULTI（链式多 hook）、SHARED（hub 代理多 hook） |
| 可选 Linker 监控 | opt-in 的 linker monitor，支持延迟 hook |
| 线程安全 | 原子写入 + mutex 保护全局状态 |
| 信号安全 | SIGSEGV/SIGBUS 保护，防止写时崩溃 |

### 1.2 shadowhook 静态库使用的核心障碍分析 — nothing.so 问题

#### 1.2.1 问题本质

shadowhook 在初始化时依赖一个辅助动态库 `libshadowhook_nothing.so`，
这是一个几乎为空的 .so（仅含一个未使用的静态变量）。
它的唯一作用是：**被 dlopen 加载后，触发 linker 创建 soinfo 结构，
供 shadowhook 扫描以逆向推断 soinfo 的内存布局**。

#### 1.2.2 完整依赖链

```
shadowhook_init()
  │
  ├─ sh_linker_init()                          ← 初始化 linker 监控
  │     │
  │     ├─ 1. 在 linker64 中查找并 hook:
  │     │      soinfo::call_constructors()      ← 拦截所有 .so 的构造函数调用
  │     │      soinfo::call_destructors()       ← 拦截所有 .so 的析构函数调用
  │     │
  │     ├─ 2. dlopen("libshadowhook_nothing.so")  ← ★ 关键步骤 ★
  │     │      │
  │     │      │  dlopen 触发 linker 为 nothing.so 创建 soinfo 结构
  │     │      │  然后调用 soinfo::call_constructors(soinfo*)
  │     │      │  ↓
  │     │      │  被步骤1 hook 的 call_constructors 拦截
  │     │      │  ↓
  │     │      ├─ sh_linker_soinfo_memory_scan_pre(soinfo*)
  │     │      │    │
  │     │      │    ├─ xdl_open("libshadowhook_nothing.so") 获取已知信息:
  │     │      │    │   phdr, phnum, load_bias, l_ld, dli_fname
  │     │      │    │
  │     │      │    └─ 在 soinfo 内存中逐字搜索这些已知值:
  │     │      │        ┌─────────────────────────────────────────────────┐
  │     │      │        │ soinfo (Android 内部结构, 每版本布局不同)        │
  │     │      │        │  offset X : phdr       ← 匹配 dlinfo.dlpi_phdr │
  │     │      │        │  offset X+8: phnum     ← 匹配 dlinfo.dlpi_phnum│
  │     │      │        │  ...                                           │
  │     │      │        │  offset Y : load_bias  ← 匹配 dlinfo.dli_fbase │
  │     │      │        │  offset Y+8: l_name    ← 含 "nothing.so"       │
  │     │      │        │  offset Y+16: l_ld     ← 匹配 PT_DYNAMIC vaddr │
  │     │      │        │  ...                                           │
  │     │      │        │  offset Y+40: constructors_called ← 此时为 0   │
  │     │      │        └─────────────────────────────────────────────────┘
  │     │      │        扫描得到 5 个关键 offset:
  │     │      │          phdr, phnum, load_bias, name, constructors_called
  │     │      │
  │     │      ├─ call_constructors 正常执行 (nothing.so 的 .init_array 为空)
  │     │      │
  │     │      └─ sh_linker_soinfo_memory_scan_post(soinfo*)
  │     │           验证 constructors_called 此时变为 1 ← 确认 offset 正确
  │     │
  │     └─ 3. dlclose("libshadowhook_nothing.so")
  │
  ├─ sh_task_init()                            ← 注册 dl_init/dl_fini 回调
  │     利用已知的 soinfo offset，从任意 soinfo 提取 dl_phdr_info
  │     监控所有后续 dlopen/dlclose 事件
  │     实现"延迟 hook": 目标 .so 未加载时，等它加载后自动 hook
  │
  └─ 初始化完成
```

#### 1.2.3 为什么阻塞静态库使用

```
根本原因: nothing.so 必须是一个 .so 文件

  ┌─ dlopen() 只能加载 .so ──────────── 必须有一个伴随 .so 文件
  │
  ├─ soinfo 是 Android linker 私有结构 ─ 布局未公开，跨版本变化
  │
  ├─ 扫描 soinfo 需要一个"已知"的 .so ── 用已知属性在内存中匹配
  │
  └─ 如果 shadowhook 本身编译为 .a ──── 不能自带 nothing.so
                                          集成方必须手动打包 nothing.so
                                          这不是真正的"纯静态库"使用

  此外，整个 sh_linker + sh_task 子系统都围绕 soinfo 监控构建:
    - hook_sym_name() 的延迟执行依赖 soinfo 监控
    - dlclose 清理依赖 soinfo 监控
    - 去掉 soinfo 监控 → 这些功能全部失效
```

#### 1.2.4 NewHook 的解决方案

**核心思路: 去除 nothing.so 运行时依赖，使用硬编码偏移 + 标准 POSIX API**

```
shadowhook 方案                          newhook 替代方案
──────────────────────────────────────   ─────────────────────────────────
nothing.so + soinfo 内存扫描              硬编码 soinfo 偏移 (nh_soinfo.h)
  运行时推断 soinfo 结构布局                通过 soinfo_parse + offsetof 验证

soinfo::call_constructors hook            可选 linker monitor (opt-in)
  监控 .so 加载事件                         从 .symtab 查找符号 + hook_func_addr

soinfo → dl_phdr_info 转换               硬编码偏移直接读取 + dl_iterate_phdr
  获取 .so 的加载信息

延迟 hook (目标 .so 未加载)               pending task 系统 (nh_task)
  等 .so 加载后自动 hook                    需先启用 linker monitor

dlclose 自动清理                          dl_fini 回调 (通过 linker monitor)
  监控析构回调

xdl (自定义 ELF 解析器)                   dl_iterate_phdr + 内联 ELF 解析
  xdl_open / xdl_sym / xdl_dsym            直接解析 PT_DYNAMIC 段
  支持 .symtab / LZMA 压缩                  仅解析 .dynsym (已映射到内存)
```

**结果: NewHook 不需要任何伴随 .so，编译为 .a 即可完全独立工作。**
**同时通过可选的 linker monitor 支持延迟 hook 和 dlclose 监控。**

linker monitor 的设计是 opt-in 的：
- 默认不启用 → 纯静态库，零外部依赖
- 调用 `newhook_init_linker_monitor()` 后启用 → 支持延迟 hook + dl_init/dl_fini 回调
- 使用硬编码 soinfo 偏移，无需 nothing.so

### 1.3 与 shadowhook 的主要差异

```
shadowhook                          newhook
─────────────────────────────────   ─────────────────────────────
ARM + ARM64 双架构                  仅 ARM64
SHARED/UNIQUE/MULTI 三模式          UNIQUE/MULTI/SHARED 三模式
Hub 代理链 + TLS 栈                 Hub 代理链 + TLS 栈 (ARM64 汇编模板)
Interceptor (CPU context 拦截)      不支持（简化）
xdl 自定义 ELF 加载器               dl_iterate_phdr + ELF 解析
nothing.so + soinfo 运行时扫描      硬编码 soinfo 偏移（无 nothing.so）
Task 异步任务/延迟hook               pending task 系统（需启用 linker monitor）
linker call_ctors/dtors hook        可选 linker monitor（从 .symtab 查找符号）
Recording 审计系统                  不支持（简化）
~4000 行代码                        ~2500 行
```

---

## 2. 整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                       Public API Layer                           │
│                      newhook.h / newhook.c                       │
│  newhook_init() / hook_func_addr[_ex]() / hook_sym_name[_ex]() │
│  unhook() / init_linker_monitor() / get_prev_func()             │
└──────────────────────────┬──────────────────────────────────────┘
                           │
       ┌───────────────────┼───────────────────────┐
       ▼                   ▼                       ▼
┌─────────────┐   ┌──────────────┐   ┌──────────────────────┐
│ nh_switch   │   │  nh_symbol   │   │  nh_linker + nh_task │
│ per-address │   │  符号解析     │   │  linker 监控          │
│ 模式调度     │   │              │   │  延迟 hook            │
└──────┬──────┘   └──────────────┘   └──────────────────────┘
       │                                      │
       ├──────────────┐                       │
       ▼              ▼                       │
┌────────────┐ ┌────────────┐                 │
│  nh_hub    │ │  nh_hook   │ ◄───────────────┘
│ SHARED模式 │ │  核心Hook  │
│ hub+TLS栈  │ │  逻辑      │
└──────┬─────┘ └──────┬─────┘
       │              │
       │       ┌──────┼───────────────┐
       │       ▼      ▼               ▼
       │ ┌──────────┐ ┌──────────┐ ┌──────────┐
       │ │  nh_a64  │ │ nh_enter │ │nh_island │
       │ │ ARM64指令│ │ Enter跳板│ │  Island  │
       │ │ 分析改写 │ │(原函数续)│ │(中间跳转)│
       │ └──────────┘ └────┬─────┘ └────┬─────┘
       │                   │            │
       ▼                   ▼            ▼
┌──────────────────────────────────────────────┐
│                  nh_trampo                    │
│            可执行内存页管理器                   │
│           (mmap RWX 分块分配)                  │
└──────────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│  nh_util (mprotect/cache flush/原子写入)      │
│  nh_safe (SIGSEGV/SIGBUS 信号保护)            │
│  nh_soinfo (硬编码 soinfo 偏移)               │
└──────────────────────────────────────────────┘
```

---

## 3. 模块详细设计

### 3.1 Public API (`newhook.h` / `newhook.c`)

#### 3.1.1 API 定义

```c
// ── 核心 API (默认 UNIQUE 模式，向后兼容) ──
int newhook_init(void);
void *newhook_hook_func_addr(void *target_addr, void *new_func, void **orig_func);
void *newhook_hook_sym_name(const char *lib_name, const char *sym_name,
                            void *new_func, void **orig_func);
int newhook_unhook(void *handle);
int newhook_get_errno(void);
const char *newhook_strerror(int errnum);

// ── 扩展 API (指定 Hook 模式) ──
// mode: NH_MODE_UNIQUE / NH_MODE_MULTI / NH_MODE_SHARED
void *newhook_hook_func_addr_ex(void *target_addr, void *new_func,
                                 void **orig_func, int mode);
void *newhook_hook_sym_name_ex(const char *lib_name, const char *sym_name,
                                void *new_func, void **orig_func, int mode);

// ── Linker 监控 (可选，启用延迟 hook) ──
int newhook_init_linker_monitor(void);

// ── SHARED 模式辅助 ──
void *newhook_get_prev_func(void *func);
void newhook_pop_stack(void *return_address);
void *newhook_get_return_address(void);
```

#### 3.1.2 内部状态管理

```c
// 全局状态（newhook.c 内部）
static pthread_mutex_t  g_lock;
static bool             g_inited;
static bool             g_linker_monitor_inited;
static _Thread_local int g_errno;   // 线程局部错误码

// newhook.c 是薄包装层，实际状态管理委托给:
//   nh_switch — per-address hook 状态 (UNIQUE/MULTI/SHARED 调度)
//   nh_hub    — SHARED 模式 hub + TLS stack
//   nh_task   — 延迟 hook pending task 队列
//   nh_linker — linker 监控 (call_constructors/call_destructors hook)
```

---

### 3.2 核心 Hook 逻辑 (`nh_hook.h` / `nh_hook.c`)

#### 3.2.1 Hook 实例结构

```c
typedef struct {
    uintptr_t  target_addr;         // 被 hook 的目标地址
    uintptr_t  new_func;            // 替换函数地址
    uintptr_t  enter;               // enter 跳板地址（调用原函数用）
    size_t     enter_size;          // enter 跳板占用大小

    uint32_t   backup[6];           // 备份的原始指令（最多 24 字节）
    size_t     backup_len;          // 备份长度（字节）

    uintptr_t  island_exit;         // island：跳转到 new_func
    uintptr_t  island_enter;        // island：从 enter 跳回原代码
    uintptr_t  island_rewrite[6];   // 改写指令用到的辅助 island

    bool       with_island;         // 是否使用 island 策略
    bool       hooked;              // 当前是否已 hook
} nh_hook_t;
```

#### 3.2.2 两种 Hook 策略

**策略 A — 带 Island（优先尝试）**

```
备份长度: 4 字节 (1 条指令)

                ┌─────────────────────────┐
                │    Island-Exit (20B)    │
                │  LDR X17, [PC, #8]     │
                │  BR  X17               │
                │  .quad <new_func>      │
                └──────────▲──────────────┘
                           │ (B 相对跳转, ±128MB)
                           │
  ┌────────────────────────┼──────────────────────────────┐
  │  Target Function       │                              │
  │  ┌─────────────────────┴───┐                          │
  │  │ [0] B <island_exit>     │ ◄── 被改写 (4B)          │
  │  │ [4] <original inst 1>   │ ◄── 原代码继续           │
  │  │ [8] ...                 │                          │
  │  └─────────────────────────┘                          │
  └───────────────────────────────────────────────────────┘
                           │
                           │ 调用原函数时:
                           ▼
  ┌──────────────────────────────────────────────────────┐
  │  Enter Trampoline (≤64B)                             │
  │  ┌──────────────────────────────────────────────┐    │
  │  │ <rewritten backup[0]>    ◄── PC修正后的指令   │    │
  │  │ B <target_addr + 4>      ◄── 跳回原代码      │    │
  │  │ (或 LDR X17 + BR X17 + addr 如果超出范围)    │    │
  │  └──────────────────────────────────────────────┘    │
  └──────────────────────────────────────────────────────┘
```

**策略 B — 无 Island（后备方案）**

```
备份长度: 16 字节 (4 条指令)

  ┌───────────────────────────────────────────────────────┐
  │  Target Function                                      │
  │  ┌─────────────────────────────┐                      │
  │  │ [0]  LDR X17, [PC, #8]     │ ◄── 直接改写 (16B)   │
  │  │ [4]  BR  X17               │                      │
  │  │ [8]  .quad <new_func>      │ ◄── 8字节地址数据     │
  │  │ [16] <original inst 4>     │ ◄── 原代码继续        │
  │  └─────────────────────────────┘                      │
  └───────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────┐
  │  Enter Trampoline (≤256B)                            │
  │  ┌──────────────────────────────────────────────┐    │
  │  │ <rewritten backup[0]>                        │    │
  │  │ <rewritten backup[1]>                        │    │
  │  │ <rewritten backup[2]>                        │    │
  │  │ <rewritten backup[3]>                        │    │
  │  │ LDR X17, [PC, #8]                           │    │
  │  │ BR  X17                                      │    │
  │  │ .quad <target_addr + 16>                     │    │
  │  └──────────────────────────────────────────────┘    │
  └──────────────────────────────────────────────────────┘
```

#### 3.2.3 Hook 安装流程

```
nh_hook_install(target_addr, new_func, &orig_func):
  │
  ├─ 1. 验证参数 (地址对齐、非 NULL)
  │
  ├─ 2. 查询符号信息 (获取函数大小，判断是否为函数起始)
  │
  ├─ 3. 尝试策略 A (带 Island)
  │     ├─ 分配 enter 跳板 (64B)
  │     ├─ 分配 island_exit (20B, 在 target ±128MB 范围内)
  │     ├─ 备份 target[0..3] (4 字节)
  │     ├─ 改写 backup[0] 到 enter 跳板
  │     ├─ 写入 enter 跳板尾部：跳回 target+4
  │     ├─ 写入 island_exit：绝对跳转到 new_func
  │     ├─ 原子写入 target[0..3] = B <island_exit>
  │     └─ 清除指令缓存
  │
  ├─ 4. 如果策略 A 失败，尝试策略 B (无 Island)
  │     ├─ 检查函数大小 >= 16 字节
  │     ├─ 分配 enter 跳板 (256B)
  │     ├─ 备份 target[0..15] (16 字节)
  │     ├─ 逐条改写 backup[0..3] 到 enter 跳板
  │     ├─ 写入 enter 跳板尾部：跳回 target+16
  │     ├─ 原子写入 target[0..15] = LDR X17 + BR X17 + addr
  │     └─ 清除指令缓存
  │
  ├─ 5. 设置 *orig_func = enter 跳板地址
  │
  └─ 6. 返回 hook 句柄
```

#### 3.2.4 Unhook 流程

```
nh_hook_uninstall(hook):
  │
  ├─ 1. 恢复原始指令
  │     ├─ mprotect(target_page, PROT_READ|PROT_WRITE|PROT_EXEC)
  │     ├─ memcpy(target_addr, backup, backup_len)
  │     ├─ __builtin___clear_cache(target_addr, target_addr + backup_len)
  │     └─ mprotect(target_page, PROT_READ|PROT_EXEC)
  │
  ├─ 2. 释放 enter 跳板 (延迟释放，防止正在执行中)
  │
  ├─ 3. 释放 island (延迟释放)
  │
  └─ 4. 标记 hook 为未激活
```

---

### 3.3 ARM64 指令分析与改写 (`nh_a64.h` / `nh_a64.c`)

这是整个框架最核心、最复杂的模块。负责将备份指令从原地址"搬迁"到 enter
跳板地址，并修正所有 PC 相关的寻址。

#### 3.3.1 需要处理的 ARM64 指令类型

| 类型 | 编码格式 | 寻址范围 | 改写策略 |
|------|----------|----------|----------|
| B | `000101 imm26` | ±128MB | 调整 imm26 或 island |
| BL | `100101 imm26` | ±128MB | 调整 imm26 或 island |
| B.cond | `01010100 imm19 0 cond` | ±1MB | 调整 imm19 或反转条件+绝对跳转 |
| CBZ | `sf 110100 0 imm19 Rt` | ±1MB | 调整 imm19 或反转+绝对跳转 |
| CBNZ | `sf 110100 1 imm19 Rt` | ±1MB | 同 CBZ |
| TBZ | `b5 011011 0 b40 imm14 Rt` | ±32KB | 调整 imm14 或反转+绝对跳转 |
| TBNZ | `b5 011011 1 b40 imm14 Rt` | ±32KB | 同 TBZ |
| ADR | `immlo 10000 immhi Rd` | ±1MB | 调整或绝对值加载 |
| ADRP | `immlo 10000 immhi Rd` | ±4GB(页对齐) | 调整或绝对值加载 |
| LDR literal (32/64) | `opc 011 0 00 imm19 Rt` | ±1MB | 调整 imm19 或间接加载 |
| LDRSW literal | `10 011 0 00 imm19 Rt` | ±1MB | 同 LDR literal |
| LDR SIMD literal | `opc 011 1 00 imm19 Rt` | ±1MB | 用 X17 做中转 |
| PRFM literal | `11 011 0 00 imm19 Rt` | ±1MB | NOP 或间接预取 |

#### 3.3.2 指令改写详细规则

**B / BL (imm26, ±128MB)**

```
原始: B <target>    在 old_pc
      target = old_pc + sign_extend(imm26) << 2

改写后位于 new_pc:
  情况 1: |target - new_pc| < 128MB
    → 直接调整 imm26 = (target - new_pc) >> 2
    → 输出: 4 字节 (1 条指令)

  情况 2: 超出范围
    → 分配 island (在 new_pc ±128MB 内)
    → island 内容: LDR X17, [PC,#8]; BR X17; .quad target
    → 改写为: B <island>  (对于 BL: BL <island>，island 内需额外处理 LR)
    → 输出: 4 字节 + 20 字节 island

  注意: BL 的 island 需要特殊处理，因为 BL 会设置 LR。
        island 中改用: LDR X17, [PC,#8]; BLR X17; .quad target
        但这会导致 LR 指向 island 而非原调用点。
        更好的方案: ADR LR, <return_addr>; LDR X17, [PC,#8]; BR X17; .quad target
```

**B.cond (imm19, ±1MB)**

```
原始: B.cond <target>    在 old_pc
      target = old_pc + sign_extend(imm19) << 2

改写:
  情况 1: |target - new_pc| < 1MB
    → 调整 imm19
    → 输出: 4 字节

  情况 2: 超出范围
    → B.inv_cond <skip>           ; 反转条件，跳过绝对跳转
    → LDR X17, [PC, #8]
    → BR X17
    → .quad <target>
    → skip:
    → 输出: 4 + 4 + 4 + 8 = 20 字节

    或使用 island (在 new_pc ±1MB 内):
    → island: LDR X17, [PC,#8]; BR X17; .quad target
    → B.cond <island>
    → 输出: 4 字节 + 20 字节 island
```

**CBZ / CBNZ (imm19, ±1MB)**

```
改写 (超出范围):
  → CBNZ/CBZ Rt, <skip>           ; 反转条件
  → LDR X17, [PC, #8]
  → BR X17
  → .quad <target>
  → skip:
  → 输出: 4 + 4 + 4 + 8 = 20 字节
```

**TBZ / TBNZ (imm14, ±32KB)**

```
改写 (超出范围):
  → TBNZ/TBZ Xt, #bit, <skip>     ; 反转条件
  → LDR X17, [PC, #8]
  → BR X17
  → .quad <target>
  → skip:
  → 输出: 20 字节
```

**ADR (±1MB)**

```
原始: ADR Rd, <label>   在 old_pc
      value = old_pc + sign_extend(immhi:immlo)

改写:
  情况 1: |value - new_pc| < 1MB
    → 调整 ADR 立即数
    → 输出: 4 字节

  情况 2: 超出范围
    → LDR Rd, [PC, #8]           ; 加载绝对地址到 Rd
    → B .+12                      ; 跳过数据
    → .quad <value>               ; 8 字节绝对地址
    → 输出: 4 + 4 + 8 = 16 字节
```

**ADRP (±4GB, 页对齐)**

```
原始: ADRP Rd, <label>  在 old_pc
      value = (old_pc & ~0xFFF) + (sign_extend(immhi:immlo) << 12)

改写:
  情况 1: new_pc 页对齐后可达
    → 调整 ADRP 立即数
    → 输出: 4 字节

  情况 2: 超出范围
    → LDR Rd, [PC, #8]
    → B .+12
    → .quad <value>
    → 输出: 16 字节
```

**LDR literal (通用寄存器, ±1MB)**

```
原始: LDR Wt/Xt, <label>  在 old_pc
      mem_addr = old_pc + sign_extend(imm19) << 2

改写 (超出范围):
  → LDR Xt, [PC, #8]             ; 先加载 mem_addr 到 Xt
  → B .+12                        ; 跳过数据
  → .quad <mem_addr>
  → LDR Wt/Xt, [Xt]              ; 再从 mem_addr 加载实际值
  → 输出: 4 + 4 + 8 + 4 = 20 字节
```

**LDR SIMD literal (SIMD 寄存器, ±1MB)**

```
改写 (超出范围, 使用 X17 做中转):
  → LDR X17, [PC, #8]            ; 加载 mem_addr 到 X17
  → B .+12
  → .quad <mem_addr>
  → LDR St/Dt/Qt, [X17]          ; 从 mem_addr 加载 SIMD 值
  → 输出: 20 字节

  注意: 会破坏 X17 (IP1)。在函数入口处这通常是安全的，
       因为 X17 是 intra-procedure-call scratch register。
```

#### 3.3.3 绝对跳转序列生成

```c
// 标准绝对跳转 (16 字节)
//   LDR X17, [PC, #8]     ; 0x58000051
//   BR  X17               ; 0xD61F0220
//   .quad <address>        ; 8 字节
size_t nh_a64_make_abs_jump(uint32_t *buf, uintptr_t addr);

// 相对跳转 (4 字节, 仅当 |target - pc| < 128MB)
//   B <target>             ; 000101 imm26
size_t nh_a64_make_rel_jump(uint32_t *buf, uintptr_t pc, uintptr_t target);
```

#### 3.3.4 改写函数签名

```c
// 改写上下文
typedef struct {
    uintptr_t  target_addr;     // 原始目标函数地址
    uintptr_t  enter_addr;      // enter 跳板基址
    uintptr_t *island_array;    // island 分配结果数组
    size_t     island_count;    // 已分配 island 数量
} nh_a64_rewrite_ctx_t;

// 改写单条指令
// 返回写入 buf 的字节数，失败返回 0
size_t nh_a64_rewrite(uint32_t *buf,          // 输出缓冲区
                      uint32_t  inst,          // 原始指令
                      uintptr_t old_pc,        // 原始 PC
                      uintptr_t new_pc,        // 新 PC (在 enter 中)
                      nh_a64_rewrite_ctx_t *ctx);

// 获取指令类型
int nh_a64_get_type(uint32_t inst);

// 获取改写后指令长度 (用于预分配)
size_t nh_a64_get_rewrite_len(uint32_t inst);
```

---

### 3.4 可执行内存管理 (`nh_trampo.h` / `nh_trampo.c`)

#### 3.4.1 设计思路

trampo (trampoline) 管理器负责分配小块可执行内存。采用页级 mmap 分配，
内部切割为固定大小的 chunk。

```
┌──────────────────────── mmap page (4KB/16KB) ────────────────────────┐
│ chunk[0] │ chunk[1] │ chunk[2] │ ... │ chunk[N-1] │ flags[0..N-1]  │
│  64/256B │  64/256B │  64/256B │     │  64/256B   │  4B each       │
└──────────────────────────────────────────────────────────────────────┘

flags 格式 (32 bit):
  bit 31    : 1=已使用, 0=空闲
  bit 30..0 : 释放时间戳 (秒级, 用于延迟复用)
```

#### 3.4.2 接口

```c
typedef struct nh_trampo_mgr nh_trampo_mgr_t;

// 初始化管理器
int nh_trampo_mgr_init(nh_trampo_mgr_t *mgr, size_t chunk_size, size_t delay_sec);

// 分配一个 chunk (可选地址范围约束)
void *nh_trampo_alloc(nh_trampo_mgr_t *mgr,
                      uintptr_t range_low,    // 0 表示无约束
                      uintptr_t range_high);   // 0 表示无约束

// 释放一个 chunk (设置延迟复用时间戳)
void nh_trampo_free(nh_trampo_mgr_t *mgr, void *ptr);

// 销毁管理器
void nh_trampo_mgr_destroy(nh_trampo_mgr_t *mgr);
```

#### 3.4.3 范围约束分配策略

当需要在特定地址范围内分配（如 island 必须在 target ±128MB 内）：

```
1. 遍历已有页面，查找范围内的空闲 chunk
2. 如果没有，尝试在范围内 mmap 新页面:
   a. 解析 /proc/self/maps 找到范围内的地址空洞
   b. 在空洞中 mmap(MAP_FIXED_NOREPLACE) 或 mmap(hint)
   c. 验证返回地址在范围内
3. 分配失败返回 NULL
```

---

### 3.5 Enter 跳板 (`nh_enter.h` / `nh_enter.c`)

Enter 跳板是一块可执行内存，包含改写后的原始指令和跳回原代码的跳转。
用户通过 `orig_func` 指针调用时，实际执行的就是 enter 跳板。

```c
// Enter 跳板大小
#define NH_ENTER_WITH_ISLAND_SIZE     64    // 策略 A: 1 条指令改写 + 跳回
#define NH_ENTER_WITHOUT_ISLAND_SIZE  256   // 策略 B: 4 条指令改写 + 跳回

// 延迟复用时间 (秒)
// 防止 unhook 后仍有线程在 enter 中执行
#define NH_ENTER_DELAY_SEC  10

// 全局 enter 管理器 (基于 nh_trampo)
static nh_trampo_mgr_t g_enter_mgr_island;     // 64B chunks
static nh_trampo_mgr_t g_enter_mgr_no_island;  // 256B chunks

void *nh_enter_alloc(bool with_island, uintptr_t target_addr);
void  nh_enter_free(void *enter, bool with_island);
```

---

### 3.6 Island 分配 (`nh_island.h` / `nh_island.c`)

Island 是一小块可执行内存，位于目标函数附近（±128MB 或 ±1MB），
用于间接跳转到远处的地址。

```c
// Island 大小
#define NH_ISLAND_SIZE  20   // LDR X17, [PC,#8]; BR X17; .quad addr

// 全局 island 管理器
static nh_trampo_mgr_t g_island_mgr;  // 20B chunks (对齐到 4B)

// 分配 island (在 target ±range 范围内)
void *nh_island_alloc(uintptr_t target, uintptr_t range);

// 释放 island
void  nh_island_free(void *island);
```

Island 用途：
- **island_exit**: 从 hook 点跳转到 new_func
- **island_enter**: 从 enter 跳板跳回原代码 (如果 enter 距离 target 太远)
- **island_rewrite**: 改写指令中的 branch/load 目标 (如果 enter 中无法直接寻址)

---

### 3.7 符号解析 (`nh_symbol.h` / `nh_symbol.c`)

#### 3.7.1 设计思路 — 去除 xdl/soinfo 依赖

shadowhook 使用自研的 xdl 库做符号解析，xdl 内部又依赖 soinfo 信息。
NewHook **完全不依赖 xdl**，改用标准 POSIX API 组合:

```
shadowhook 符号解析:                    newhook 符号解析:
───────────────────                    ──────────────────
xdl_open(lib_name)                     dl_iterate_phdr() 遍历已加载 ELF
  → 通过 soinfo 链表查找                  → POSIX 标准 API, 无私有结构依赖
xdl_sym(handle, sym_name)              解析 PT_DYNAMIC 段的 .dynsym
  → 解析 .dynsym                         → 内存中直接读取，无需打开文件
xdl_dsym(handle, sym_name)             (可选) dlsym() 辅助
  → 解析 .symtab (从文件读取)              → 用于简单场景的快速查找
```

**不支持 .symtab 解析**（.symtab 需要从 ELF 文件读取 section header，
不在内存映射中）。这意味着只能 hook 导出的动态符号。
对于绝大多数 inline hook 场景（hook libc、libart 等系统库的导出函数），
这已经足够。

#### 3.7.2 数据结构

```c
typedef struct {
    uintptr_t addr;      // 符号地址
    size_t    size;      // 符号大小 (st_size)
    bool      found;     // 是否找到
} nh_symbol_info_t;

// 按库名+符号名查找 (仅查找 .dynsym)
int nh_symbol_find(const char *lib_name,
                   const char *sym_name,
                   nh_symbol_info_t *info);

// 按地址反查符号信息 (用于确定函数大小)
// 利用 dladdr() 标准 API 或遍历 .dynsym
int nh_symbol_find_by_addr(uintptr_t addr,
                           nh_symbol_info_t *info);
```

#### 3.7.3 ELF 解析流程

```
nh_symbol_find(lib_name, sym_name, &info):
  │
  ├─ dl_iterate_phdr(callback, ctx)    ← POSIX 标准 API
  │
  └─ callback(struct dl_phdr_info *phdr_info, ...):
       │
       ├─ 匹配 lib_name
       │     比较 phdr_info->dlpi_name 的 basename
       │     支持: "libc.so", "libtarget.so", 完整路径, NULL(任意库)
       │
       ├─ 在 phdr 数组中查找 PT_DYNAMIC 段
       │     for (i = 0; i < dlpi_phnum; i++)
       │       if (dlpi_phdr[i].p_type == PT_DYNAMIC) → 找到
       │
       ├─ 遍历 .dynamic 条目提取关键表指针
       │     uintptr_t dyn_addr = dlpi_addr + p_vaddr;
       │     for each Elf64_Dyn entry:
       │       DT_SYMTAB  → symtab 指针  (Elf64_Sym 数组)
       │       DT_STRTAB  → strtab 指针  (字符串表)
       │       DT_HASH    → nchain 值    (符号数量, 传统 hash)
       │       DT_GNU_HASH → 通过 bucket/chain 计算符号数量
       │
       ├─ 遍历 .dynsym 符号表查找目标符号
       │     for (i = 0; i < sym_count; i++):
       │       Elf64_Sym *sym = &symtab[i];
       │       if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC) continue;
       │       if (strcmp(strtab + sym->st_name, sym_name) != 0) continue;
       │       info->addr = dlpi_addr + sym->st_value;
       │       info->size = sym->st_size;
       │       return 1; // 停止迭代
       │
       └─ 返回 0 继续迭代下一个 ELF

nh_symbol_find_by_addr(addr, &info):
  │
  ├─ 方案 A: dladdr(addr, &dl_info)   ← 标准 API, 但不返回 sym_size
  │     info->addr = dl_info.dli_saddr;
  │     info->size = 0;  // dladdr 不提供大小信息
  │
  └─ 方案 B: dl_iterate_phdr 遍历 .dynsym
       查找 st_value 范围包含 addr 的符号
       info->addr = dlpi_addr + sym->st_value;
       info->size = sym->st_size;
```

#### 3.7.4 GNU Hash 符号数量计算

.dynsym 的符号数量不在 PT_DYNAMIC 中直接给出。
需要通过 hash 表间接计算:

```
传统 DT_HASH:
  struct { uint32_t nbucket; uint32_t nchain; ... };
  sym_count = nchain;

GNU DT_GNU_HASH (Android 6.0+):
  struct { uint32_t nbuckets; uint32_t symoffset; uint32_t bloom_size; ... };
  需要遍历 bucket 和 chain 找到最大符号索引:
    max_idx = 0;
    for (i = 0; i < nbuckets; i++)
      if (bucket[i] > max_idx) max_idx = bucket[i];
    // 然后沿 chain 走到末尾 (chain[i] & 1 == 1 表示结束)
    sym_count = max_idx + trailing_chain_length;
```

---

### 3.8 信号安全 (`nh_safe.h` / `nh_safe.c`)

在写入目标函数内存时（hook/unhook），可能遇到：
- 页面不可写 (mprotect 可能失败或竞争)
- 目标地址无效

使用信号处理器保护写入操作：

```c
// 注册 SIGSEGV/SIGBUS 信号处理器
int nh_safe_init(void);

// 安全执行一段代码 (类似 try-catch)
// 如果触发 SIGSEGV/SIGBUS，会通过 sigsetjmp 返回非零值
#define NH_SAFE_CALL(code_block) do {               \
    if (sigsetjmp(nh_safe_jmp_buf, 1) == 0) {      \
        code_block;                                  \
    } else {                                         \
        /* signal caught, write failed */            \
    }                                                \
} while(0)
```

---

### 3.9 工具函数 (`nh_util.h` / `nh_util.c`)

```c
// ─── 位操作 ───
#define NH_BITS_GET(val, hi, lo)   // 提取位域
#define NH_SIGN_EXTEND(val, bits)  // 符号扩展

// ─── 对齐 ───
#define NH_PAGE_START(addr)  ((addr) & ~(page_size - 1))
#define NH_PAGE_END(addr)    NH_PAGE_START((addr) + page_size - 1)

// ─── 内存操作 ───
int   nh_util_mprotect(uintptr_t addr, size_t len, int prot);
void  nh_util_flush_cache(uintptr_t addr, size_t len);

// ─── 原子写入指令 ───
// 使用 __atomic_store 确保对齐写入的原子性
void nh_util_write_inst(uintptr_t addr, const void *data, size_t len);

// ─── 页大小 ───
size_t nh_util_get_page_size(void);
```

---

## 4. 线程安全设计

### 4.1 全局锁

```
g_switches_lock (pthread_mutex_t, in nh_switch.c):
  保护: g_switches 链表, g_handles 链表, hook/unhook 操作
  粒度: 每次 hook/unhook 调用持有

g_tasks_lock (pthread_mutex_t, in nh_task.c):
  保护: g_tasks pending task 链表

g_init_cbs_lock / g_fini_cbs_lock (pthread_rwlock_t, in nh_linker.c):
  保护: dl_init/dl_fini 回调链表
  读写锁: 回调触发时读锁，注册/注销时写锁
```

### 4.2 原子指令写入

```
hook 安装时的指令写入:
  4 字节 (策略 A): 使用 __atomic_store_n (4B, __ATOMIC_SEQ_CST)
  16 字节 (策略 B): 需要分步写入
    1. 先写 [8..15] (地址数据)    ← 其他线程即使读到也无害
    2. 再写 [0..7]  (LDR + BR)    ← 原子 8 字节写入激活 hook
    3. 全内存屏障 __atomic_thread_fence(__ATOMIC_SEQ_CST)

MULTI 模式 proxy 链更新:
  __atomic_store_n(prev->orig_addr, new_addr, __ATOMIC_RELEASE)
  确保链式调用在更新过程中不会读到不一致的指针

SHARED 模式 hub proxy 链:
  proxy 插入: __atomic_store_n(&hub->proxies, proxy, __ATOMIC_RELEASE)
  proxy 读取: __atomic_load_n(&hub->proxies, __ATOMIC_ACQUIRE)
  enabled 标志: __atomic_store_n / __atomic_load_n
```

### 4.3 SHARED 模式 TLS 栈

```
per-thread stack (nh_hub_stack_t):
  - pthread_key_create + destructor 管理生命周期
  - 预分配 512 个 stack 缓存池，避免热路径 mmap/malloc
  - 最多 16 层嵌套 hook 调用
  - 递归调用检测: 扫描 frames 中是否有相同 orig_addr
```

### 4.4 延迟释放

```
unhook 后的 enter 跳板和 island 不能立即回收:
  - 可能有线程正在 enter 跳板中执行
  - 使用时间戳标记释放时间
  - 新分配时检查: 只复用 delay_sec 之前释放的 chunk
  - 默认延迟: 10 秒
```

---

## 5. 构建系统

### 5.1 CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.10)
project(newhook C ASM)

# 源文件
set(SOURCES
    src/newhook.c
    src/nh_hook.c
    src/nh_a64.c
    src/nh_trampo.c
    src/nh_enter.c
    src/nh_island.c
    src/nh_symbol.c
    src/nh_util.c
    src/nh_safe.c
    src/nh_switch.c
    src/nh_hub.c
    src/nh_hub_trampo.S
    src/nh_linker.c
    src/nh_task.c
)

# 编译选项 (ARM64 only)
set(COMMON_FLAGS
    -std=c11
    -Wall -Wextra -Werror
    -ffunction-sections
    -fdata-sections
    -fvisibility=hidden
)

# 静态库
add_library(newhook_static STATIC ${SOURCES})
target_include_directories(newhook_static PUBLIC include PRIVATE src)
target_compile_options(newhook_static PRIVATE ${COMMON_FLAGS})
set_target_properties(newhook_static PROPERTIES OUTPUT_NAME newhook)

# 动态库
add_library(newhook_shared SHARED ${SOURCES})
target_include_directories(newhook_shared PUBLIC include PRIVATE src)
target_compile_options(newhook_shared PRIVATE ${COMMON_FLAGS})
target_link_options(newhook_shared PRIVATE
    -Wl,--gc-sections
    -Wl,--version-script=${CMAKE_SOURCE_DIR}/newhook.map
)
target_link_libraries(newhook_shared PRIVATE dl log)
set_target_properties(newhook_shared PROPERTIES OUTPUT_NAME newhook)
```

### 5.2 符号导出 (newhook.map)

```
NEWHOOK_1.0 {
  global:
    newhook_init;
    newhook_hook_func_addr;
    newhook_hook_sym_name;
    newhook_unhook;
    newhook_get_errno;
    newhook_strerror;
    newhook_hook_func_addr_ex;
    newhook_hook_sym_name_ex;
    newhook_init_linker_monitor;
    newhook_get_prev_func;
    newhook_pop_stack;
    newhook_get_return_address;
  local:
    *;
};
```

---

## 6. 文件清单与职责

```
newhook/
├── include/
│   └── newhook.h              # 公共 API 头文件 (模式常量/错误码/核心+扩展 API)
├── src/
│   ├── newhook.c              # API 实现, 委托给 nh_switch/nh_task/nh_hub
│   ├── nh_switch.c/h          # per-address 状态管理, UNIQUE/MULTI/SHARED 调度
│   ├── nh_hub.c/h             # SHARED 模式 hub (proxy 链 + TLS stack)
│   ├── nh_hub_trampo.S        # ARM64 hub trampoline 汇编模板
│   ├── nh_linker.c/h          # linker 监控 (hook call_constructors/destructors)
│   ├── nh_task.c/h            # 延迟 hook pending task 系统
│   ├── nh_soinfo.h            # 硬编码 soinfo 偏移 (ARM64 LP64)
│   ├── nh_hook.c/h            # 核心 hook/unhook 逻辑 (指令级 patch)
│   ├── nh_a64.c/h             # ARM64 指令分析与改写 (13 类 PC 相对指令)
│   ├── nh_trampo.c/h          # 可执行内存块管理 (mmap RWX 分块)
│   ├── nh_enter.c/h           # enter 跳板管理 (调用原始函数)
│   ├── nh_island.c/h          # island 分配管理 (±128MB 中间跳转)
│   ├── nh_symbol.c/h          # ELF 符号解析 (dl_iterate_phdr + .dynsym)
│   ├── nh_safe.c/h            # 信号安全保护 (SIGSEGV/SIGBUS)
│   ├── nh_util.c/h            # 工具函数 (mprotect/cache flush/原子写入)
│   ├── nh_errno.h             # 错误码定义
│   └── nh_log.h               # Android 日志宏
├── test/
│   └── test_newhook.c         # 30 个测试用例
├── soinfoparse/               # soinfo 偏移解析/验证工具
│   ├── soinfo_parse.c         # hook call_constructors 内存扫描
│   ├── soinfo_calc.c          # offsetof 镜像结构体验证
│   └── libshadowhook_nothing.so
├── CMakeLists.txt             # CMake 构建 (C + ASM, shared + static + test)
├── newhook.map                # 符号导出脚本 (12 个导出符号)
├── push_test.bat              # 一键构建 + ADB 推送 + 运行脚本
├── DESIGN.md                  # 本设计文档
└── README.md                  # 快速入门文档
```

---

## 7. 使用示例

### 7.1 UNIQUE 模式（默认）

```c
#include "newhook.h"
#include <stdio.h>

static int (*orig_open)(const char *path, int flags, ...);

int my_open(const char *path, int flags, ...) {
    printf("open(\"%s\", %d)\n", path, flags);
    return orig_open(path, flags);
}

int main() {
    newhook_init();

    void *h = newhook_hook_sym_name(
        "libc.so", "open", (void *)my_open, (void **)&orig_open);

    open("/tmp/test", 0);  // 触发 hook
    newhook_unhook(h);
    return 0;
}
```

### 7.2 MULTI 模式（链式多 hook）

```c
#include "newhook.h"
#include <stdio.h>
#include <stdlib.h>

static int (*orig_abs_1)(int) = NULL;
static int (*orig_abs_2)(int) = NULL;

int hook_abs_1(int x) {
    printf("hook1: abs(%d)\n", x);
    return orig_abs_1(x);  // 调用链中下一个 → hook2
}

int hook_abs_2(int x) {
    printf("hook2: abs(%d)\n", x);
    return orig_abs_2(x);  // 调用原始函数
}

int main() {
    newhook_init();

    // 同一地址挂两个 hook，通过 orig_func 指针自动链接
    void *h1 = newhook_hook_func_addr_ex(
        (void *)abs, (void *)hook_abs_1, (void **)&orig_abs_1, NH_MODE_MULTI);
    void *h2 = newhook_hook_func_addr_ex(
        (void *)abs, (void *)hook_abs_2, (void **)&orig_abs_2, NH_MODE_MULTI);

    abs(-42);  // hook1 → hook2 → 原始 abs

    newhook_unhook(h2);  // 移除 hook2，链自动重建
    abs(-42);  // hook1 → 原始 abs

    newhook_unhook(h1);
    return 0;
}
```

### 7.3 SHARED 模式（hub 代理多 hook）

```c
#include "newhook.h"
#include <stdio.h>
#include <stdlib.h>

int hook_a(int x) {
    printf("hook_a: abs(%d)\n", x);
    // 获取链中下一个函数（另一个 hook 或原始函数）
    int (*prev)(int) = (int (*)(int))newhook_get_prev_func((void *)hook_a);
    return prev(x);
}

int hook_b(int x) {
    printf("hook_b: abs(%d)\n", x);
    int (*prev)(int) = (int (*)(int))newhook_get_prev_func((void *)hook_b);
    return prev(x);
}

int main() {
    newhook_init();

    void *ha = newhook_hook_func_addr_ex(
        (void *)abs, (void *)hook_a, NULL, NH_MODE_SHARED);
    void *hb = newhook_hook_func_addr_ex(
        (void *)abs, (void *)hook_b, NULL, NH_MODE_SHARED);

    abs(-42);  // hub → hook_a → hook_b → 原始 abs

    newhook_unhook(ha);  // 禁用 hook_a
    abs(-42);  // hub → hook_b → 原始 abs

    newhook_unhook(hb);
    return 0;
}
```

### 7.4 延迟 Hook（目标库未加载）

```c
#include "newhook.h"
#include <dlfcn.h>
#include <stdio.h>

static int (*orig_target)(int) = NULL;

int my_hook(int x) {
    printf("hooked! x=%d\n", x);
    return orig_target(x);
}

int main() {
    newhook_init();
    newhook_init_linker_monitor();  // 启用 linker 监控

    // 此时 libfoo.so 尚未加载，hook 进入 pending 状态
    void *h = newhook_hook_sym_name_ex(
        "libfoo.so", "target_func",
        (void *)my_hook, (void **)&orig_target, NH_MODE_UNIQUE);
    // h != NULL, newhook_get_errno() == NH_ERR_PENDING

    // 稍后加载库，hook 自动激活
    dlopen("libfoo.so", RTLD_NOW);
    // target_func 现在已被 hook

    newhook_unhook(h);  // 同时清理 pending task 和已激活的 hook
    return 0;
}
```

---

## 8. 关键设计决策总结

| 决策 | 选择 | 理由 |
|------|------|------|
| 架构支持 | 仅 ARM64 | 需求限定，减少代码量和条件编译 |
| Hook 模式 | UNIQUE / MULTI / SHARED | 覆盖全部使用场景 |
| 跳板寄存器 | X17 (IP1) | ARM64 ABI 规定的临时寄存器，不影响调用约定 |
| 内存管理 | 页内分块 | 减少 mmap 系统调用，高效复用 |
| 线程安全 | mutex + atomic | 简洁可靠，hook 操作非高频 |
| 符号解析 | dl_iterate_phdr + .dynsym | 去除 xdl/soinfo 依赖，纯标准 API |
| linker 监控 | 可选 (opt-in) | 默认无依赖；需要延迟 hook 时手动启用 |
| soinfo 偏移 | 硬编码 | 通过 soinfo_parse + offsetof 双重验证，无需 nothing.so |
| 延迟 hook | pending task 系统 | 库加载时自动激活，需先启用 linker monitor |
| 延迟释放 | 10 秒时间戳 | 平衡安全性和内存回收效率 |
| 信号保护 | sigsetjmp/siglongjmp | 处理意外 SIGSEGV，不依赖外部库 |

---

## 9. nothing.so 问题与静态库支持 — 总结

```
shadowhook 的问题:
  静态库 (.a) ──→ 编译时不需要伴随 .so
                   但运行时仍需 libshadowhook_nothing.so ──→ 不是真正的"纯静态库"
                   如果忘记打包 nothing.so → 初始化失败
                   UE4/游戏引擎集成时容易遗漏

newhook 的解决:
  静态库 (.a) ──→ 编译时无伴随 .so
                   运行时无外部依赖 ──→ 真正的纯静态库
                   直接 link 到宿主 .so 或可执行文件即可
                   UE4 集成: 在 Build.cs 中 add_library + target_link_libraries 即可
```

---

## 10. MULTI / SHARED 模式架构

### 10.1 nh_switch — per-address 状态管理

`nh_switch` 是 newhook 的核心调度模块，管理每个目标地址的 hook 状态。参考 shadowhook 的 `sh_switch.c`。

```
newhook_hook_func_addr_ex(target, new_func, &orig, mode)
  │
  └─ nh_switch_hook(target, new_func, &orig, mode, sym_size)
       │
       ├─ find_switch(target)  ← 查找已有 switch
       │
       ├─ mode == UNIQUE:
       │    ├─ 已有 switch → NH_ERR_ALREADY_HOOKED
       │    └─ 新建 switch + nh_hook_install → 返回 handle
       │
       ├─ mode == MULTI:
       │    ├─ 已有 UNIQUE switch → NH_ERR_MODE_CONFLICT
       │    ├─ 首次: 新建 switch + proxy, nh_hook_install 指向 proxy->new_addr
       │    └─ 后续: 追加 proxy 到链尾, 原子更新 prev->orig_addr
       │
       └─ mode == SHARED:
            ├─ 已有 UNIQUE switch → NH_ERR_MODE_CONFLICT
            ├─ 首次: 新建 switch + hub, nh_hook_install 指向 hub trampoline
            └─ 后续: hub_add_proxy(new_func)
```

### 10.2 MULTI 模式 — 指针链

MULTI 模式通过 `orig_func` 指针实现链式调用，与 shadowhook 的 `sh_switch_proxy_add/del` 完全一致。

```
调用流程 (3 个 hook):

  目标函数入口
    │ (被 patch 为跳转到 hook1)
    ▼
  hook1(x)
    │ orig1 ──→ hook2
    ▼
  hook2(x)
    │ orig2 ──→ hook3
    ▼
  hook3(x)
    │ orig3 ──→ 原始函数 (enter trampoline)
    ▼
  原始函数
```

unhook 中间节点时，原子更新前一个节点的 `orig_addr` 跳过被移除的节点：

```
unhook hook2:
  before: orig1 → hook2, orig2 → hook3
  after:  orig1 → hook3  (atomic store)
```

### 10.3 SHARED 模式 — Hub 代理

SHARED 模式使用 hub trampoline 作为统一入口，通过 TLS per-thread stack 管理调用链。参考 shadowhook 的 `sh_hub.c`。

```
调用流程:

  目标函数入口
    │ (被 patch 为跳转到 hub trampoline)
    ▼
  Hub Trampoline (nh_hub_trampo.S):
    │ 1. 保存 x0-x8, lr, q0-q7 到栈
    │ 2. 调用 nh_hub_push_stack_impl(hub, lr)
    │    → 获取 TLS stack, 推入 frame, 返回第一个 enabled proxy
    │ 3. 恢复所有寄存器
    │ 4. br x16 → 跳转到 proxy
    ▼
  proxy_a(x)
    │ newhook_get_prev_func(proxy_a) → proxy_b
    ▼
  proxy_b(x)
    │ newhook_get_prev_func(proxy_b) → 原始函数
    ▼
  原始函数
```

Hub 数据结构：

```c
nh_hub_t {
  proxies → [proxy_a(enabled)] → [proxy_b(enabled)] → NULL
  orig_addr = enter trampoline (原始函数)
  trampo = hub trampoline 地址
}

nh_hub_stack_t (TLS, per-thread) {
  frames[0] = { proxies snapshot, orig_addr, return_address }
  frames_cnt = 1
}
```

unhook 时仅将 proxy 的 `enabled` 设为 false（不从链表移除），遍历时自动跳过。

---

## 11. Linker 监控架构

### 11.1 nh_linker — hook linker64

newhook 的 linker 监控不依赖 nothing.so 运行时扫描，而是使用硬编码的 soinfo 偏移（通过 `soinfoparse` 工具验证）。

```
newhook_init_linker_monitor()
  │
  ├─ nh_linker_init()
  │    ├─ 从 /proc/self/maps 获取 linker64 基址和路径
  │    ├─ mmap linker64 ELF, 从 .symtab 查找:
  │    │    __dl__ZN6soinfo17call_constructorsEv
  │    │    __dl__ZN6soinfo16call_destructorsEv
  │    ├─ 计算运行时地址 = 基址 + 偏移
  │    └─ newhook_hook_func_addr() hook 两个函数
  │
  └─ nh_task_init()
       └─ 注册 dl_init pre-callback → task_dl_init_pre
```

### 11.2 soinfo 硬编码偏移

在 `nh_soinfo.h` 中定义，通过两种方式验证：

1. `soinfo_parse` — 在设备上 hook call_constructors，拿到 soinfo 指针后内存扫描
2. `soinfo_calc` — 用 `offsetof` 对镜像结构体计算

```
ARM64 LP64 soinfo 偏移 (Android 16 API 36):
  [  0] phdr
  [  8] phnum
  [208] link_map.l_addr (== load_bias)
  [216] link_map.l_name
  [248] constructors_called
  [256] load_bias
```

### 11.3 nh_task — 延迟 Hook

```
newhook_hook_sym_name_ex("libfoo.so", "func", ...)
  │
  ├─ nh_symbol_find() → 失败 (库未加载)
  │
  ├─ linker monitor 已启用?
  │    ├─ 是 → nh_task_create() → 返回 task handle (errno=NH_ERR_PENDING)
  │    └─ 否 → 返回 NULL (errno=NH_ERR_SYMBOL_NOT_FOUND)
  │
  ... 稍后 libfoo.so 被 dlopen ...
  │
  linker proxy_call_constructors(soinfo)
    │ nh_soinfo_to_dlinfo(soinfo, &dlinfo)
    │ 触发 dl_init pre-callbacks
    ▼
  task_dl_init_pre(dlinfo)
    │ 遍历 pending tasks
    │ 匹配 lib_name → nh_symbol_find() → 成功
    │ nh_switch_hook() → 安装 hook
    └─ task.is_finished = true
```

unhook 时自动检测 handle 类型（task magic `0x4E485441`），如果是 task 则调用 `nh_task_destroy`，内部会 unhook 已激活的 switch。
