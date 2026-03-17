// newhook - ARM64 inline hook library
// Supports both shared (.so) and static (.a) library builds.
// No companion .so required (no nothing.so / soinfo dependency).

#ifndef NEWHOOK_H
#define NEWHOOK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Symbol visibility: export public API when building .so
#if defined(__GNUC__) || defined(__clang__)
#define NH_EXPORT __attribute__((visibility("default")))
#else
#define NH_EXPORT
#endif

// error codes
#define NH_OK                     0
#define NH_ERR_INVALID_ARG        1
#define NH_ERR_NOT_INITIALIZED    2
#define NH_ERR_ALREADY_HOOKED     3
#define NH_ERR_NOT_HOOKED         4
#define NH_ERR_ALLOC_ENTER        5
#define NH_ERR_ALLOC_ISLAND       6
#define NH_ERR_REWRITE            7
#define NH_ERR_MPROTECT           8
#define NH_ERR_SYMBOL_NOT_FOUND   9
#define NH_ERR_FUNC_TOO_SMALL    10
#define NH_ERR_PATCH             11
#define NH_ERR_SAFE_INIT         12
#define NH_ERR_OOM               13
#define NH_ERR_MODE_CONFLICT     14
#define NH_ERR_HUB               15
#define NH_ERR_PENDING           16
#define NH_ERR_DUP               17
#define NH_ERR_LINKER_INIT       18

// hook modes
#define NH_MODE_UNIQUE  0   // one hook per address (default)
#define NH_MODE_SHARED  1   // multiple hooks via hub proxy chain
#define NH_MODE_MULTI   2   // multiple hooks via orig_addr pointer chaining

// ── Core API (backward compatible, defaults to NH_MODE_UNIQUE) ──

NH_EXPORT int newhook_init(void);

NH_EXPORT void *newhook_hook_func_addr(void *target_addr, void *new_func, void **orig_func);

NH_EXPORT void *newhook_hook_sym_name(const char *lib_name, const char *sym_name,
                                      void *new_func, void **orig_func);

NH_EXPORT int newhook_unhook(void *handle);

NH_EXPORT int newhook_get_errno(void);

NH_EXPORT const char *newhook_strerror(int errnum);

// ── Extended API (mode-aware) ──

NH_EXPORT void *newhook_hook_func_addr_ex(void *target_addr, void *new_func,
                                           void **orig_func, int mode);

NH_EXPORT void *newhook_hook_sym_name_ex(const char *lib_name, const char *sym_name,
                                          void *new_func, void **orig_func, int mode);

// ── Linker monitoring (optional, enables delayed hooks) ──

NH_EXPORT int newhook_init_linker_monitor(void);

// ── SHARED mode helpers ──
// Call from within a SHARED-mode hook to get the next function in the chain.
NH_EXPORT void *newhook_get_prev_func(void *func);

// Call at the end of a SHARED-mode hook to pop the stack frame.
NH_EXPORT void newhook_pop_stack(void *return_address);

// Get the original return address saved by the hub trampoline.
NH_EXPORT void *newhook_get_return_address(void);

#ifdef __cplusplus
}
#endif

#endif // NEWHOOK_H
