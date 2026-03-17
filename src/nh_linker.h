#ifndef NH_LINKER_H
#define NH_LINKER_H

#include <link.h>
#include <stddef.h>

// Callback type for dl_init/dl_fini notifications.
// info: standard dl_phdr_info extracted from soinfo via hardcoded offsets.
typedef void (*nh_dl_info_cb_t)(struct dl_phdr_info *info, size_t size, void *data);

// Initialize linker monitoring:
//   1. Find call_constructors/call_destructors in linker64
//   2. Hook them using newhook_hook_func_addr (UNIQUE mode)
//   3. Use hardcoded soinfo offsets to extract dl_phdr_info in callbacks
// Returns 0 on success.
int nh_linker_init(void);

// Register dl_init callbacks (called when soinfo::call_constructors fires).
int nh_linker_register_dl_init_cb(nh_dl_info_cb_t pre, nh_dl_info_cb_t post, void *data);
int nh_linker_unregister_dl_init_cb(nh_dl_info_cb_t pre, nh_dl_info_cb_t post, void *data);

// Register dl_fini callbacks (called when soinfo::call_destructors fires).
int nh_linker_register_dl_fini_cb(nh_dl_info_cb_t pre, nh_dl_info_cb_t post, void *data);
int nh_linker_unregister_dl_fini_cb(nh_dl_info_cb_t pre, nh_dl_info_cb_t post, void *data);

#endif // NH_LINKER_H
