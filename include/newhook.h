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

NH_EXPORT int newhook_init(void);

NH_EXPORT void *newhook_hook_func_addr(void *target_addr, void *new_func, void **orig_func);

NH_EXPORT void *newhook_hook_sym_name(const char *lib_name, const char *sym_name,
                                      void *new_func, void **orig_func);

NH_EXPORT int newhook_unhook(void *handle);

NH_EXPORT int newhook_get_errno(void);

NH_EXPORT const char *newhook_strerror(int errnum);

#ifdef __cplusplus
}
#endif

#endif // NEWHOOK_H
