# newhook

Android ARM64 inline hook 库，支持静态库 (.a) 与动态库 (.so) 双模式构建。

基于 POSIX 标准 API 实现符号解析，**无需任何伴生 .so**（彻底消除 shadowhook 的 `nothing.so` / soinfo 依赖），可作为纯静态库直接链接到任意可执行文件或动态库中。

## 特性

- **纯静态库可用** — 无运行时伴生 .so 依赖，`libnewhook.a` 即可独立工作
- **ARM64 专精** — 仅支持 `arm64-v8a`，无条件编译分支，代码精简
- **三种 Hook 模式** — UNIQUE（单 hook）、MULTI（链式多 hook）、SHARED（hub 代理多 hook）
- **Linker 监控** — 可选的 linker monitor，hook linker64 的 call_constructors/call_destructors
- **延迟 Hook** — 目标库未加载时自动创建 pending task，库加载后自动激活
- **双 hook 策略** — 优先 4 字节 island 方案，自动回退 16 字节直接 patch
- **13 类 PC 相对指令重写** — 覆盖 B/BL/B.cond/CBZ/CBNZ/TBZ/TBNZ/ADR/ADRP/LDR literal/PRFM 等全部场景
- **线程安全** — 全局互斥锁 + 原子指令写入 + 线程本地 errno
- **信号保护** — SIGSEGV/SIGBUS handler，patch 写入失败不崩溃

## 快速开始

### 1. 构建

```bash
# 配置（需要 Android NDK）
cmake -DCMAKE_BUILD_TYPE=Debug \
      -S . -B build -G "MinGW Makefiles"

# 编译
cmake --build build --parallel
```

产物：
- `build/libnewhook.a` — 静态库
- `build/libnewhook.so` — 动态库
- `build/newhook_test` — 测试可执行文件

### 2. 设备测试

```bash
adb push build/newhook_test /data/local/tmp/newhook_test
adb shell chmod 755 /data/local/tmp/newhook_test
adb shell /data/local/tmp/newhook_test
```

或直接运行一键脚本：

```bat
push_test.bat
```

### 3. 集成到你的项目

**静态链接（推荐）：**

```cmake
add_library(newhook STATIC IMPORTED)
set_target_properties(newhook PROPERTIES IMPORTED_LOCATION ${PATH_TO}/libnewhook.a)
target_include_directories(your_target PRIVATE ${PATH_TO}/include)
target_link_libraries(your_target newhook log dl)
```

**动态链接：**

```cmake
add_library(newhook SHARED IMPORTED)
set_target_properties(newhook PROPERTIES IMPORTED_LOCATION ${PATH_TO}/libnewhook.so)
target_include_directories(your_target PRIVATE ${PATH_TO}/include)
target_link_libraries(your_target newhook)
```

## API

```c
#include "newhook.h"
```

### 核心 API（默认 UNIQUE 模式）

```c
int newhook_init(void);

void *newhook_hook_func_addr(void *target_addr, void *new_func, void **orig_func);

void *newhook_hook_sym_name(const char *lib_name, const char *sym_name,
                            void *new_func, void **orig_func);

int newhook_unhook(void *handle);

int newhook_get_errno(void);
const char *newhook_strerror(int errnum);
```

### 扩展 API（指定 Hook 模式）

```c
// mode: NH_MODE_UNIQUE / NH_MODE_MULTI / NH_MODE_SHARED
void *newhook_hook_func_addr_ex(void *target_addr, void *new_func,
                                 void **orig_func, int mode);

void *newhook_hook_sym_name_ex(const char *lib_name, const char *sym_name,
                                void *new_func, void **orig_func, int mode);
```

### Linker 监控（可选）

```c
// 初始化 linker 监控，启用延迟 hook 支持
int newhook_init_linker_monitor(void);
```

### SHARED 模式辅助函数

```c
// 在 SHARED 模式 hook 回调中获取链中下一个函数
void *newhook_get_prev_func(void *func);

// 弹出 hub 栈帧
void newhook_pop_stack(void *return_address);

// 获取 hub 保存的原始返回地址
void *newhook_get_return_address(void);
```

## Hook 模式

### UNIQUE 模式（默认）

每个地址只允许一个 hook。最简单、开销最低。

```c
void *h = newhook_hook_func_addr(target, my_func, &orig_func);
// 或
void *h = newhook_hook_func_addr_ex(target, my_func, &orig_func, NH_MODE_UNIQUE);
```

### MULTI 模式

同一地址可挂多个 hook，通过 `orig_func` 指针链式调用。每个 hook 的 `orig_func` 会被动态更新，指向链中的下一个 hook（或原始函数）。

```c
static int (*orig1)(int) = NULL;
static int (*orig2)(int) = NULL;

int hook1(int x) { return orig1(x); }  // orig1 -> hook2
int hook2(int x) { return orig2(x); }  // orig2 -> 原始函数

void *h1 = newhook_hook_func_addr_ex(target, hook1, (void **)&orig1, NH_MODE_MULTI);
void *h2 = newhook_hook_func_addr_ex(target, hook2, (void **)&orig2, NH_MODE_MULTI);
```

### SHARED 模式

同一地址可挂多个 hook，通过 hub 代理分发。使用 `newhook_get_prev_func()` 获取链中下一个函数。

```c
int hook_a(int x) {
    int (*prev)(int) = (int (*)(int))newhook_get_prev_func((void *)hook_a);
    return prev(x);
}

int hook_b(int x) {
    int (*prev)(int) = (int (*)(int))newhook_get_prev_func((void *)hook_b);
    return prev(x);
}

void *ha = newhook_hook_func_addr_ex(target, hook_a, NULL, NH_MODE_SHARED);
void *hb = newhook_hook_func_addr_ex(target, hook_b, NULL, NH_MODE_SHARED);
```

## 延迟 Hook

当目标库尚未加载时，`newhook_hook_sym_name_ex` 会创建一个 pending task，在库加载后自动激活 hook。需要先初始化 linker 监控：

```c
newhook_init();
newhook_init_linker_monitor();  // 启用 linker 监控

// 此时 libfoo.so 尚未加载
void *h = newhook_hook_sym_name_ex("libfoo.so", "target_func",
                                    my_func, &orig_func, NH_MODE_UNIQUE);
// h != NULL, errno == NH_ERR_PENDING

// 稍后当 libfoo.so 被 dlopen 时，hook 自动激活
dlopen("libfoo.so", RTLD_NOW);
// 此时 target_func 已被 hook
```

## 错误码

| 常量 | 值 | 说明 |
|------|----|------|
| `NH_OK` | 0 | 成功 |
| `NH_ERR_INVALID_ARG` | 1 | 无效参数 |
| `NH_ERR_NOT_INITIALIZED` | 2 | 未调用 newhook_init |
| `NH_ERR_ALREADY_HOOKED` | 3 | 该地址已被 hook（UNIQUE 模式） |
| `NH_ERR_NOT_HOOKED` | 4 | 句柄未找到或已 unhook |
| `NH_ERR_ALLOC_ENTER` | 5 | enter 跳板内存分配失败 |
| `NH_ERR_ALLOC_ISLAND` | 6 | island 分配失败 |
| `NH_ERR_REWRITE` | 7 | ARM64 指令重写失败 |
| `NH_ERR_MPROTECT` | 8 | 内存页权限修改失败 |
| `NH_ERR_SYMBOL_NOT_FOUND` | 9 | 符号未找到 |
| `NH_ERR_FUNC_TOO_SMALL` | 10 | 目标函数体太小 |
| `NH_ERR_PATCH` | 11 | 指令 patch 写入失败 |
| `NH_ERR_SAFE_INIT` | 12 | 信号处理器注册失败 |
| `NH_ERR_OOM` | 13 | 内存分配失败 |
| `NH_ERR_MODE_CONFLICT` | 14 | 同一地址 hook 模式冲突 |
| `NH_ERR_HUB` | 15 | hub 创建/操作失败 |
| `NH_ERR_PENDING` | 16 | hook 处于 pending 状态（库未加载） |
| `NH_ERR_DUP` | 17 | 重复 hook |
| `NH_ERR_LINKER_INIT` | 18 | linker 监控初始化失败 |

## 项目结构

```
newhook/
├── include/
│   └── newhook.h              # 公共 API
├── src/
│   ├── newhook.c              # API 实现、全局状态管理
│   ├── nh_hook.c/h            # hook 安装/卸载核心逻辑
│   ├── nh_switch.c/h          # per-address 状态管理 (UNIQUE/MULTI/SHARED 调度)
│   ├── nh_hub.c/h             # SHARED 模式 hub (proxy 链 + TLS stack)
│   ├── nh_hub_trampo.S        # ARM64 hub trampoline 汇编模板
│   ├── nh_linker.c/h          # linker 监控 (hook call_constructors/destructors)
│   ├── nh_task.c/h            # 延迟 hook pending task 系统
│   ├── nh_soinfo.h            # soinfo 硬编码偏移 (ARM64 LP64)
│   ├── nh_a64.c/h             # ARM64 指令分析与重写引擎
│   ├── nh_trampo.c/h          # 可执行内存页管理器
│   ├── nh_enter.c/h           # enter 跳板分配
│   ├── nh_island.c/h          # island 分配 (±128MB)
│   ├── nh_symbol.c/h          # ELF 符号解析
│   ├── nh_safe.c/h            # 信号保护
│   ├── nh_util.c/h            # 工具函数
│   ├── nh_errno.h             # 错误码定义
│   └── nh_log.h               # Android 日志宏
├── test/
│   └── test_newhook.c         # 30 个测试用例
├── soinfoparse/               # soinfo 偏移解析工具
├── CMakeLists.txt             # 构建配置
├── newhook.map                # .so 符号导出脚本
├── push_test.bat              # 一键构建 + ADB 推送 + 运行脚本
├── DESIGN.md                  # 详细架构设计文档
└── README.md                  # 本文档
```

## 测试套件

共 30 个测试用例：

| 分类 | 数量 | 内容 |
|------|------|------|
| 基本功能 | 7 | init、hook_func_addr、hook_sym_name、double hook、rehook、invalid args、modify return |
| 安全性与鲁棒性 | 13 | 多 hook 并发、线程安全、多参数、caller state、压力测试、double unhook、递归调用 |
| MULTI 模式 | 4 | 双 hook 链式调用、unhook 中间节点、unhook 全部恢复、模式冲突检测 |
| SHARED 模式 | 3 | 双 hook hub 代理、unhook 一个另一个仍工作、unhook 全部恢复 |
| Linker 监控 | 3 | linker monitor init、dlopen 检测回调、延迟 hook pending |

## 与 shadowhook 的对比

| 维度 | shadowhook | newhook |
|------|-----------|---------|
| 静态库支持 | 不支持（需要 nothing.so） | 完整支持 |
| soinfo 依赖 | 运行时扫描（需 nothing.so） | 硬编码偏移（无运行时依赖） |
| 符号解析 | 自定义 xdl 库 | 标准 dl_iterate_phdr |
| 架构支持 | ARM + ARM64 | ARM64 专精 |
| Hook 模式 | SHARED / UNIQUE / MULTI | UNIQUE / MULTI / SHARED |
| Linker 监控 | hook linker constructors | 可选 linker monitor |
| 延迟 hook | 支持 | 支持（需启用 linker monitor） |
| 代码量 | ~4000 行 | ~2500 行 |

## 构建要求

- Android NDK r25c 或兼容版本
- CMake 3.10+
- 目标平台：Android API 26+ (arm64-v8a)

## 许可证

本项目代码仅供学习研究使用。
