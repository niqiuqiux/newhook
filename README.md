# newhook

Android ARM64 inline hook 库，支持静态库 (.a) 与动态库 (.so) 双模式构建。

基于 POSIX 标准 API 实现符号解析，**无需任何伴生 .so**（彻底消除 shadowhook 的 `nothing.so` / soinfo 依赖），可作为纯静态库直接链接到任意可执行文件或动态库中。

## 特性

- **纯静态库可用** — 无运行时伴生 .so 依赖，`libnewhook.a` 即可独立工作
- **ARM64 专精** — 仅支持 `arm64-v8a`，无条件编译分支，代码精简
- **双 hook 策略** — 优先 4 字节 island 方案，自动回退 16 字节直接 patch
- **13 类 PC 相对指令重写** — 覆盖 B/BL/B.cond/CBZ/CBNZ/TBZ/TBNZ/ADR/ADRP/LDR literal/PRFM 等全部场景
- **线程安全** — 全局互斥锁 + 原子指令写入 + 线程本地 errno
- **信号保护** — SIGSEGV/SIGBUS handler，patch 写入失败不崩溃
- **约 1500 行 C 代码** — 相比 shadowhook ~4000 行，大幅精简

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

### newhook_init

```c
int newhook_init(void);
```

初始化库。进程中调用一次即可，重复调用安全。
返回 `NH_OK` 或错误码。

### newhook_hook_func_addr

```c
void *newhook_hook_func_addr(void *target_addr, void *new_func, void **orig_func);
```

按函数地址安装 hook。

| 参数 | 说明 |
|------|------|
| `target_addr` | 目标函数地址（必须 4 字节对齐） |
| `new_func` | 替换函数地址 |
| `orig_func` | 输出：指向原始函数的跳板指针（可为 NULL） |

返回 hook 句柄（非 NULL 表示成功）。`*orig_func` 在 hook 生效前就已写入，回调中可安全使用。

### newhook_hook_sym_name

```c
void *newhook_hook_sym_name(const char *lib_name, const char *sym_name,
                            void *new_func, void **orig_func);
```

按符号名安装 hook。

| 参数 | 说明 |
|------|------|
| `lib_name` | 库名（如 `"libc.so"`），NULL 表示搜索所有已加载库 |
| `sym_name` | 符号名 |
| `new_func` | 替换函数地址 |
| `orig_func` | 输出：指向原始函数的跳板指针（可为 NULL） |

### newhook_unhook

```c
int newhook_unhook(void *handle);
```

移除 hook，恢复原始指令。返回 `NH_OK` 或错误码。
跳板内存使用延迟回收（enter: 10s, island: 3s），确保正在执行的线程不会访问已释放内存。

### newhook_get_errno / newhook_strerror

```c
int newhook_get_errno(void);
const char *newhook_strerror(int errnum);
```

获取当前线程的错误码 / 错误描述。errno 是线程本地的，多线程安全。

## 使用示例

```c
#include "newhook.h"
#include <stdlib.h>
#include <stdio.h>

// 保存原始函数指针
static int (*orig_atoi)(const char *) = NULL;

// 替换函数
static int my_atoi(const char *s) {
    printf("atoi called with: %s\n", s);
    return orig_atoi(s);  // 调用原始函数
}

int main(void) {
    newhook_init();

    // 按符号名 hook
    void *handle = newhook_hook_sym_name(
        "libc.so", "atoi",
        (void *)my_atoi, (void **)&orig_atoi
    );

    if (handle == NULL) {
        printf("hook failed: %s\n", newhook_strerror(newhook_get_errno()));
        return 1;
    }

    int val = atoi("12345");  // 会触发 my_atoi
    printf("result: %d\n", val);

    newhook_unhook(handle);   // 恢复原始函数
    return 0;
}
```

## 错误码

| 常量 | 值 | 说明 |
|------|----|------|
| `NH_OK` | 0 | 成功 |
| `NH_ERR_INVALID_ARG` | 1 | 无效参数（NULL 指针、未对齐地址） |
| `NH_ERR_NOT_INITIALIZED` | 2 | 未调用 newhook_init |
| `NH_ERR_ALREADY_HOOKED` | 3 | 该地址已被 hook（UNIQUE 模式） |
| `NH_ERR_NOT_HOOKED` | 4 | 句柄未找到或已 unhook |
| `NH_ERR_ALLOC_ENTER` | 5 | enter 跳板内存分配失败 |
| `NH_ERR_ALLOC_ISLAND` | 6 | island 分配失败（±128MB 范围内无可用内存） |
| `NH_ERR_REWRITE` | 7 | ARM64 指令重写失败 |
| `NH_ERR_MPROTECT` | 8 | 内存页权限修改失败 |
| `NH_ERR_SYMBOL_NOT_FOUND` | 9 | 符号未找到 |
| `NH_ERR_FUNC_TOO_SMALL` | 10 | 目标函数体 < 16 字节（策略 B 不可用） |
| `NH_ERR_PATCH` | 11 | 指令 patch 写入失败 |
| `NH_ERR_SAFE_INIT` | 12 | 信号处理器注册失败 |
| `NH_ERR_OOM` | 13 | 内存分配失败 |

## 架构

### Hook 策略

newhook 采用两级策略，优先选择最小侵入方案：

**策略 A — Island 方案（优先）**

仅修改目标函数首条指令（4 字节）：

```
目标函数:           Island (±128MB 内):        Enter 跳板:
┌──────────┐       ┌──────────────────┐       ┌─────────────────┐
│ B <island>│──────>│ LDR X17, [PC,#8] │       │ 重写的原始指令   │
│ ...       │       │ BR  X17           │       │ B/LDR 跳回原函数 │
└──────────┘       │ .quad <new_func>  │       └─────────────────┘
                   └──────────────────┘
```

**策略 B — 直接 Patch（回退）**

当 ±128MB 内无法分配 island 时，直接覆盖 16 字节：

```
目标函数:                               Enter 跳板:
┌──────────────────┐                   ┌──────────────────────┐
│ LDR X17, [PC,#8] │                   │ 4 条重写的原始指令     │
│ BR  X17           │                   │ 绝对跳转回原函数+16   │
│ .quad <new_func>  │                   └──────────────────────┘
│ (原第4条指令被覆盖) │
└──────────────────┘
```

### 符号解析

不依赖 linker 私有结构（soinfo），使用标准 POSIX API：

```
dl_iterate_phdr()
  └─> 遍历每个已加载 ELF
       └─> 查找 PT_DYNAMIC segment
            └─> 解析 DT_SYMTAB / DT_STRTAB / DT_GNU_HASH
                 └─> 遍历 .dynsym 匹配符号名
```

支持 `DT_GNU_HASH`（现代 Android 首选）和 `DT_HASH`（传统回退），自动处理 PIE 可执行文件的 d_ptr 重定位偏移。

### ARM64 指令重写

支持全部 13 类 PC 相对指令的安全重写：

| 类别 | 指令 | 原始范围 | 超范围处理 |
|------|------|---------|-----------|
| 无条件跳转 | B, BL | ±128MB | 绝对跳转 (16B) |
| 条件跳转 | B.cond | ±1MB | 反转条件 + 绝对跳转 (20B) |
| 比较跳转 | CBZ, CBNZ | ±1MB | 反转条件 + 绝对跳转 (20B) |
| 位测试跳转 | TBZ, TBNZ | ±32KB | 反转条件 + 绝对跳转 (20B) |
| 地址计算 | ADR, ADRP | ±1MB / ±4GB | 绝对地址加载 (16B) |
| 字面量加载 | LDR (32/64/SW) | ±1MB | 地址加载 + 间接读取 (20B) |
| SIMD 字面量 | LDR (S/D/Q) | ±1MB | 地址加载 + SIMD 读取 (20B) |
| 预取 | PRFM | ±1MB | 替换为 NOP (4B) |

非 PC 相对指令直接复制，无需重写。

## 项目结构

```
newhook/
├── include/
│   └── newhook.h           # 公共 API（6 个函数 + 13 个错误码）
├── src/
│   ├── newhook.c           # API 实现、全局状态管理
│   ├── nh_hook.c/h         # hook 安装/卸载核心逻辑
│   ├── nh_a64.c/h          # ARM64 指令分析与重写引擎
│   ├── nh_trampo.c/h       # 可执行内存页管理器（RWX mmap + 分块）
│   ├── nh_enter.c/h        # enter 跳板分配（调用原始函数）
│   ├── nh_island.c/h       # island 分配（±128MB 范围中间跳板）
│   ├── nh_symbol.c/h       # ELF 符号解析（dl_iterate_phdr + .dynsym）
│   ├── nh_safe.c/h         # 信号保护（SIGSEGV/SIGBUS 捕获）
│   ├── nh_util.c/h         # 工具函数（mprotect、缓存刷新、原子写入）
│   ├── nh_errno.h          # 错误码定义
│   └── nh_log.h            # Android 日志宏
├── test/
│   └── test_newhook.c      # 20 个测试用例
├── CMakeLists.txt           # 构建配置
├── newhook.map              # .so 符号导出脚本
├── push_test.bat            # 一键构建 + ADB 推送 + 运行脚本
├── DESIGN.md                # 详细架构设计文档
└── README.md                # 本文档
```

## 测试套件

共 20 个测试用例，分为基本功能和安全性两大类：

### 基本功能 (7)

| # | 测试名 | 验证内容 |
|---|--------|---------|
| 1 | newhook_init | 初始化 + 重复初始化安全 |
| 2 | hook_func_addr | 按地址 hook strlen，调用原始函数，unhook 恢复 |
| 3 | hook_sym_name | 按符号名 hook libc.so 中的 atoi |
| 4 | double hook | 同一地址重复 hook 返回 NH_ERR_ALREADY_HOOKED |
| 5 | rehook | hook → unhook → 再 hook 完整生命周期 |
| 6 | invalid arguments | NULL 指针、不存在符号等边界输入 |
| 7 | modify return | hook 替换函数返回值 |

### 安全性与鲁棒性 (13)

| # | 测试名 | 验证内容 |
|---|--------|---------|
| 8 | multi hook | 3 个函数同时 hook，逐个 unhook 互不干扰 |
| 9 | thread concurrent | 4 线程 × 1000 次并发调用 hooked 函数 |
| 10 | thread hook/unhook | 工作线程持续调用 + 主线程反复 hook/unhook（竞态） |
| 11 | thread errno | 线程间 errno 隔离（thread-local） |
| 12 | many args | hook snprintf（多参数），验证寄存器传递完整 |
| 13 | caller state | hook 不破坏调用者的局部变量和寄存器状态 |
| 14 | 100 cycles | 100 次 hook/call/unhook 循环（内存管理压力） |
| 15 | 4 hooks | 4 个函数同时 hook（跳板分配器压力） |
| 16 | double unhook | 二次 unhook 返回错误不崩溃 |
| 17 | orig_func=NULL | 不需要原始函数指针的场景 |
| 18 | nonexistent lib | 不存在的库 + NULL 库名全局搜索 |
| 19 | recursive call | hook 回调中调用 orig 不会重入（深度恒为 1） |
| 20 | arg passing | INT_MAX/INT_MIN/前导空格/尾随字符等边界输入 |

## 与 shadowhook 的对比

| 维度 | shadowhook | newhook |
|------|-----------|---------|
| 静态库支持 | 不支持（需要 nothing.so） | 完整支持 |
| soinfo 依赖 | 依赖（逆向 linker 内部结构） | 无依赖（POSIX API） |
| 符号解析 | 自定义 xdl 库 | 标准 dl_iterate_phdr |
| 架构支持 | ARM + ARM64 | ARM64 专精 |
| Hook 模式 | SHARED / UNIQUE / MULTI | UNIQUE |
| Linker 监控 | hook linker constructors | 无 |
| 延迟 hook | 支持（等待库加载） | 不支持（目标库须已加载） |
| 代码量 | ~4000 行 | ~1500 行 |

**适用场景：** 需要纯静态链接、仅面向 ARM64、目标库在 hook 时已加载的场景。

## 构建要求

- Android NDK r25c 或兼容版本
- CMake 3.10+
- 目标平台：Android API 26+ (arm64-v8a)

## 许可证

本项目代码仅供学习研究使用。
