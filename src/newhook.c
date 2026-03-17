#include "newhook.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "nh_enter.h"
#include "nh_hub.h"
#include "nh_island.h"
#include "nh_linker.h"
#include "nh_log.h"
#include "nh_safe.h"
#include "nh_switch.h"
#include "nh_symbol.h"
#include "nh_task.h"
#include "nh_util.h"

// ============================================================
// Global state
// ============================================================

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_inited = false;
static bool g_linker_monitor_inited = false;
static _Thread_local int g_errno = NH_OK;

// ============================================================
// Error helpers
// ============================================================

static void set_errno(int err) {
  g_errno = err;
}

static void *fail(int err) {
  set_errno(err);
  return NULL;
}

// ============================================================
// Public API: init
// ============================================================

int newhook_init(void) {
  pthread_mutex_lock(&g_lock);

  if (g_inited) {
    pthread_mutex_unlock(&g_lock);
    return NH_OK;
  }

  if (nh_safe_init() != 0) {
    pthread_mutex_unlock(&g_lock);
    set_errno(NH_ERR_SAFE_INIT);
    return NH_ERR_SAFE_INIT;
  }

  nh_enter_init();
  nh_island_init();
  nh_switch_init();
  nh_hub_init();

  g_inited = true;
  pthread_mutex_unlock(&g_lock);

  NH_LOG_I("newhook initialized (ARM64, page_size=%zu)", nh_util_get_page_size());
  return NH_OK;
}

// ============================================================
// Public API: hook by address
// ============================================================

void *newhook_hook_func_addr(void *target_addr, void *new_func, void **orig_func) {
  return newhook_hook_func_addr_ex(target_addr, new_func, orig_func, NH_MODE_UNIQUE);
}

void *newhook_hook_func_addr_ex(void *target_addr, void *new_func,
                                 void **orig_func, int mode) {
  if (!g_inited) return fail(NH_ERR_NOT_INITIALIZED);
  if (target_addr == NULL || new_func == NULL) return fail(NH_ERR_INVALID_ARG);
  if (((uintptr_t)target_addr & 0x3) != 0) return fail(NH_ERR_INVALID_ARG);

  // best-effort symbol size lookup
  nh_symbol_info_t sym_info;
  size_t sym_size = 0;
  if (nh_symbol_find_by_addr((uintptr_t)target_addr, &sym_info) == 0) {
    sym_size = sym_info.size;
  }

  nh_switch_handle_t *handle = nh_switch_hook(
      (uintptr_t)target_addr, (uintptr_t)new_func, orig_func, mode, sym_size);

  if (!handle) {
    // determine specific error
    if (mode == NH_MODE_UNIQUE) {
      set_errno(NH_ERR_ALREADY_HOOKED);
    } else if (mode == NH_MODE_SHARED) {
      set_errno(NH_ERR_HUB);
    } else {
      set_errno(NH_ERR_MODE_CONFLICT);
    }
    return NULL;
  }

  set_errno(NH_OK);
  return handle;
}

// ============================================================
// Public API: hook by symbol name
// ============================================================

void *newhook_hook_sym_name(const char *lib_name, const char *sym_name,
                            void *new_func, void **orig_func) {
  return newhook_hook_sym_name_ex(lib_name, sym_name, new_func, orig_func, NH_MODE_UNIQUE);
}

void *newhook_hook_sym_name_ex(const char *lib_name, const char *sym_name,
                                void *new_func, void **orig_func, int mode) {
  if (!g_inited) return fail(NH_ERR_NOT_INITIALIZED);
  if (sym_name == NULL || new_func == NULL) return fail(NH_ERR_INVALID_ARG);

  nh_symbol_info_t sym_info;
  if (nh_symbol_find(lib_name, sym_name, &sym_info) != 0) {
    // symbol not found — if linker monitor active, create pending task
    if (g_linker_monitor_inited && lib_name != NULL) {
      nh_task_t *task = nh_task_create(lib_name, sym_name,
                                       (uintptr_t)new_func, orig_func, mode);
      if (task) {
        set_errno(NH_ERR_PENDING);
        return task;
      }
    }
    return fail(NH_ERR_SYMBOL_NOT_FOUND);
  }

  nh_switch_handle_t *handle = nh_switch_hook(
      sym_info.addr, (uintptr_t)new_func, orig_func, mode, sym_info.size);

  if (!handle) {
    if (mode == NH_MODE_UNIQUE) {
      set_errno(NH_ERR_ALREADY_HOOKED);
    } else {
      set_errno(NH_ERR_MODE_CONFLICT);
    }
    return NULL;
  }

  set_errno(NH_OK);
  return handle;
}

// ============================================================
// Public API: unhook
// ============================================================

int newhook_unhook(void *h) {
  if (!g_inited) { set_errno(NH_ERR_NOT_INITIALIZED); return NH_ERR_NOT_INITIALIZED; }
  if (h == NULL) { set_errno(NH_ERR_INVALID_ARG); return NH_ERR_INVALID_ARG; }

  // check if this is a pending task handle
  if (nh_task_is_task(h)) {
    int r = nh_task_destroy((nh_task_t *)h);
    set_errno(r);
    return r;
  }

  int r = nh_switch_unhook((nh_switch_handle_t *)h);
  set_errno(r);
  return r;
}

// ============================================================
// Public API: linker monitor (stub)
// ============================================================

int newhook_init_linker_monitor(void) {
  if (!g_inited) { set_errno(NH_ERR_NOT_INITIALIZED); return NH_ERR_NOT_INITIALIZED; }
  if (g_linker_monitor_inited) { set_errno(NH_OK); return NH_OK; }

  int r = nh_linker_init();
  if (r != 0) { set_errno(NH_ERR_LINKER_INIT); return NH_ERR_LINKER_INIT; }

  r = nh_task_init();
  if (r != 0) { set_errno(NH_ERR_LINKER_INIT); return NH_ERR_LINKER_INIT; }

  g_linker_monitor_inited = true;
  set_errno(NH_OK);
  return NH_OK;
}

// ============================================================
// Public API: SHARED mode helpers
// ============================================================

void *newhook_get_prev_func(void *func) {
  return nh_hub_get_prev_func(func);
}

void newhook_pop_stack(void *return_address) {
  nh_hub_pop_stack(return_address);
}

void *newhook_get_return_address(void) {
  return nh_hub_get_return_address();
}

// ============================================================
// Public API: error
// ============================================================

int newhook_get_errno(void) {
  return g_errno;
}

const char *newhook_strerror(int errnum) {
  switch (errnum) {
    case NH_OK:                  return "success";
    case NH_ERR_INVALID_ARG:     return "invalid argument";
    case NH_ERR_NOT_INITIALIZED: return "not initialized";
    case NH_ERR_ALREADY_HOOKED:  return "address already hooked";
    case NH_ERR_NOT_HOOKED:      return "address not hooked";
    case NH_ERR_ALLOC_ENTER:     return "failed to allocate enter trampoline";
    case NH_ERR_ALLOC_ISLAND:    return "failed to allocate island";
    case NH_ERR_REWRITE:         return "instruction rewrite failed";
    case NH_ERR_MPROTECT:        return "mprotect failed";
    case NH_ERR_SYMBOL_NOT_FOUND:return "symbol not found";
    case NH_ERR_FUNC_TOO_SMALL:  return "function too small for hook";
    case NH_ERR_PATCH:           return "failed to patch target";
    case NH_ERR_SAFE_INIT:       return "signal handler init failed";
    case NH_ERR_OOM:             return "out of memory";
    case NH_ERR_MODE_CONFLICT:   return "hook mode conflict on same address";
    case NH_ERR_HUB:             return "hub creation/operation failed";
    case NH_ERR_PENDING:         return "hook pending (library not loaded)";
    case NH_ERR_DUP:             return "duplicate hook";
    case NH_ERR_LINKER_INIT:     return "linker monitor init failed";
    default:                     return "unknown error";
  }
}
