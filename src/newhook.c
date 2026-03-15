#include "newhook.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "nh_enter.h"
#include "nh_hook.h"
#include "nh_island.h"
#include "nh_log.h"
#include "nh_safe.h"
#include "nh_symbol.h"
#include "nh_util.h"

// ============================================================
// Global state
// ============================================================

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_inited = false;
static _Thread_local int g_errno = NH_OK;

// Hook handle: wraps nh_hook_t with a linked list node
typedef struct nh_handle {
  nh_hook_t hook;
  struct nh_handle *next;
} nh_handle_t;

static nh_handle_t *g_handles = NULL;

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
// Public API
// ============================================================

int newhook_init(void) {
  pthread_mutex_lock(&g_lock);

  if (g_inited) {
    pthread_mutex_unlock(&g_lock);
    return NH_OK;
  }

  // Initialize signal safety
  if (nh_safe_init() != 0) {
    pthread_mutex_unlock(&g_lock);
    set_errno(NH_ERR_SAFE_INIT);
    return NH_ERR_SAFE_INIT;
  }

  // Initialize memory managers
  nh_enter_init();
  nh_island_init();

  g_inited = true;
  pthread_mutex_unlock(&g_lock);

  NH_LOG_I("newhook initialized (ARM64, page_size=%zu)", nh_util_get_page_size());
  return NH_OK;
}

void *newhook_hook_func_addr(void *target_addr, void *new_func, void **orig_func) {
  if (!g_inited) return fail(NH_ERR_NOT_INITIALIZED);
  if (target_addr == NULL || new_func == NULL) return fail(NH_ERR_INVALID_ARG);
  if (((uintptr_t)target_addr & 0x3) != 0) return fail(NH_ERR_INVALID_ARG);  // must be 4-byte aligned

  pthread_mutex_lock(&g_lock);

  // Check if already hooked at this address
  for (nh_handle_t *h = g_handles; h != NULL; h = h->next) {
    if (h->hook.target_addr == (uintptr_t)target_addr && h->hook.hooked) {
      pthread_mutex_unlock(&g_lock);
      return fail(NH_ERR_ALREADY_HOOKED);
    }
  }

  // Allocate handle
  nh_handle_t *handle = calloc(1, sizeof(nh_handle_t));
  if (handle == NULL) {
    pthread_mutex_unlock(&g_lock);
    return fail(NH_ERR_OOM);
  }

  // Try to get symbol size for the target address (best-effort)
  nh_symbol_info_t sym_info;
  size_t sym_size = 0;
  if (nh_symbol_find_by_addr((uintptr_t)target_addr, &sym_info) == 0) {
    sym_size = sym_info.size;
  }

  // Install the hook
  // orig_func is passed directly — the strategy sets it BEFORE the patch
  // takes effect, so the hook callback can use it immediately.
  int r = nh_hook_install(&handle->hook, (uintptr_t)target_addr,
                          (uintptr_t)new_func, orig_func, sym_size);
  if (r != NH_OK) {
    free(handle);
    pthread_mutex_unlock(&g_lock);
    return fail(r);
  }

  // Add to global list
  handle->next = g_handles;
  g_handles = handle;

  pthread_mutex_unlock(&g_lock);
  set_errno(NH_OK);
  return handle;
}

void *newhook_hook_sym_name(const char *lib_name, const char *sym_name,
                            void *new_func, void **orig_func) {
  if (!g_inited) return fail(NH_ERR_NOT_INITIALIZED);
  if (sym_name == NULL || new_func == NULL) return fail(NH_ERR_INVALID_ARG);

  // Resolve symbol
  nh_symbol_info_t sym_info;
  if (nh_symbol_find(lib_name, sym_name, &sym_info) != 0) {
    return fail(NH_ERR_SYMBOL_NOT_FOUND);
  }

  pthread_mutex_lock(&g_lock);

  // Check if already hooked
  for (nh_handle_t *h = g_handles; h != NULL; h = h->next) {
    if (h->hook.target_addr == sym_info.addr && h->hook.hooked) {
      pthread_mutex_unlock(&g_lock);
      return fail(NH_ERR_ALREADY_HOOKED);
    }
  }

  // Allocate handle
  nh_handle_t *handle = calloc(1, sizeof(nh_handle_t));
  if (handle == NULL) {
    pthread_mutex_unlock(&g_lock);
    return fail(NH_ERR_OOM);
  }

  // Install the hook
  // orig_func is passed directly — set before patch takes effect.
  int r = nh_hook_install(&handle->hook, sym_info.addr,
                          (uintptr_t)new_func, orig_func, sym_info.size);
  if (r != NH_OK) {
    free(handle);
    pthread_mutex_unlock(&g_lock);
    return fail(r);
  }

  handle->next = g_handles;
  g_handles = handle;

  pthread_mutex_unlock(&g_lock);
  set_errno(NH_OK);
  return handle;
}

int newhook_unhook(void *h) {
  if (!g_inited) { set_errno(NH_ERR_NOT_INITIALIZED); return NH_ERR_NOT_INITIALIZED; }
  if (h == NULL) { set_errno(NH_ERR_INVALID_ARG); return NH_ERR_INVALID_ARG; }

  nh_handle_t *handle = (nh_handle_t *)h;

  pthread_mutex_lock(&g_lock);

  // Verify handle is in our list
  bool found = false;
  for (nh_handle_t *p = g_handles; p != NULL; p = p->next) {
    if (p == handle) { found = true; break; }
  }
  if (!found) {
    pthread_mutex_unlock(&g_lock);
    set_errno(NH_ERR_NOT_HOOKED);
    return NH_ERR_NOT_HOOKED;
  }

  // Uninstall
  int r = nh_hook_uninstall(&handle->hook);
  if (r != NH_OK) {
    pthread_mutex_unlock(&g_lock);
    set_errno(r);
    return r;
  }

  // Remove from list
  if (g_handles == handle) {
    g_handles = handle->next;
  } else {
    for (nh_handle_t *p = g_handles; p != NULL; p = p->next) {
      if (p->next == handle) {
        p->next = handle->next;
        break;
      }
    }
  }

  free(handle);

  pthread_mutex_unlock(&g_lock);
  set_errno(NH_OK);
  return NH_OK;
}

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
    default:                     return "unknown error";
  }
}
