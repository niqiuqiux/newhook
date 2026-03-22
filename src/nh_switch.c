#include "nh_switch.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "newhook.h"
#include "nh_hook.h"
#include "nh_hub.h"
#include "nh_log.h"

// ============================================================================
// Switch modes (internal)
// ============================================================================

#define NH_SWITCH_MODE_NONE    -1
#define NH_SWITCH_MODE_UNIQUE   NH_MODE_UNIQUE
#define NH_SWITCH_MODE_SHARED   NH_MODE_SHARED
#define NH_SWITCH_MODE_MULTI    NH_MODE_MULTI

// ============================================================================
// MULTI mode proxy
// ============================================================================

typedef struct nh_multi_proxy {
  uintptr_t new_addr;
  uintptr_t *orig_addr;          // user-provided pointer, dynamically updated
  struct nh_multi_proxy *prev;
  struct nh_multi_proxy *next;
} nh_multi_proxy_t;

// ============================================================================
// Forward declaration for hub
// ============================================================================

struct nh_hub;

// ============================================================================
// Per-target-address switch
// ============================================================================

typedef struct nh_switch {
  uintptr_t target_addr;
  int hook_mode;
  nh_hook_t inst;                 // low-level instruction hook
  uintptr_t resume_addr;         // enter trampoline (original function)

  // UNIQUE mode
  uintptr_t unique_new_addr;

  // MULTI mode
  nh_multi_proxy_t *proxies_head;
  nh_multi_proxy_t *proxies_tail;

  // SHARED mode
  struct nh_hub *hub;

  struct nh_switch *next;
} nh_switch_t;

// ============================================================================
// Handle returned to user
// ============================================================================

struct nh_switch_handle {
  nh_switch_t *sw;
  int mode;
  uintptr_t new_func;
  struct nh_switch_handle *next_handle;  // for validity tracking
};

// ============================================================================
// Global state
// ============================================================================

static pthread_mutex_t g_switches_lock = PTHREAD_MUTEX_INITIALIZER;
static nh_switch_t *g_switches = NULL;

// Track all live handles for validity checking
static nh_switch_handle_t *g_handles = NULL;

static void track_handle(nh_switch_handle_t *h) {
  h->next_handle = g_handles;
  g_handles = h;
}

static bool untrack_handle(nh_switch_handle_t *h) {
  if (g_handles == h) {
    g_handles = h->next_handle;
    return true;
  }
  for (nh_switch_handle_t *p = g_handles; p; p = p->next_handle) {
    if (p->next_handle == h) {
      p->next_handle = h->next_handle;
      return true;
    }
  }
  return false;
}

void nh_switch_init(void) {
  // nothing needed for now
}

// ============================================================================
// Internal: find switch by target address
// ============================================================================

static nh_switch_t *find_switch(uintptr_t target_addr) {
  for (nh_switch_t *sw = g_switches; sw != NULL; sw = sw->next) {
    if (sw->target_addr == target_addr) return sw;
  }
  return NULL;
}

// ============================================================================
// Internal: create a new switch and install instruction hook
// ============================================================================

static nh_switch_t *create_switch(uintptr_t target_addr, uintptr_t new_func,
                                  void **orig_func, size_t sym_size, int *out_err) {
  nh_switch_t *sw = calloc(1, sizeof(nh_switch_t));
  if (!sw) { if (out_err) *out_err = NH_ERR_OOM; return NULL; }

  sw->target_addr = target_addr;
  sw->hook_mode = NH_SWITCH_MODE_NONE;

  int r = nh_hook_install(&sw->inst, target_addr, new_func, orig_func, sym_size);
  if (r != NH_OK) {
    if (out_err) *out_err = r;
    free(sw);
    return NULL;
  }

  sw->resume_addr = sw->inst.enter;

  // add to global list
  sw->next = g_switches;
  g_switches = sw;

  return sw;
}

// ============================================================================
// Internal: destroy switch and uninstall instruction hook
// ============================================================================

static void destroy_switch(nh_switch_t *sw) {
  if (sw->inst.hooked) {
    nh_hook_uninstall(&sw->inst);
  }

  // remove from global list
  if (g_switches == sw) {
    g_switches = sw->next;
  } else {
    for (nh_switch_t *p = g_switches; p != NULL; p = p->next) {
      if (p->next == sw) {
        p->next = sw->next;
        break;
      }
    }
  }

  free(sw);
}

// ============================================================================
// UNIQUE mode
// ============================================================================

static nh_switch_handle_t *hook_unique(uintptr_t target_addr, uintptr_t new_func,
                                       void **orig_func, size_t sym_size,
                                       int *out_err) {
  nh_switch_t *sw = find_switch(target_addr);

  if (sw != NULL) {
    if (out_err) *out_err = (sw->hook_mode == NH_SWITCH_MODE_UNIQUE)
                            ? NH_ERR_ALREADY_HOOKED : NH_ERR_MODE_CONFLICT;
    return NULL;
  }

  sw = create_switch(target_addr, new_func, orig_func, sym_size, out_err);
  if (!sw) return NULL;

  sw->hook_mode = NH_SWITCH_MODE_UNIQUE;
  sw->unique_new_addr = new_func;

  nh_switch_handle_t *handle = calloc(1, sizeof(nh_switch_handle_t));
  if (!handle) {
    destroy_switch(sw);
    if (out_err) *out_err = NH_ERR_OOM;
    return NULL;
  }

  handle->sw = sw;
  handle->mode = NH_MODE_UNIQUE;
  handle->new_func = new_func;

  return handle;
}

static int unhook_unique(nh_switch_handle_t *handle) {
  nh_switch_t *sw = handle->sw;

  sw->unique_new_addr = 0;
  sw->hook_mode = NH_SWITCH_MODE_NONE;
  destroy_switch(sw);

  free(handle);
  return NH_OK;
}

// ============================================================================
// MULTI mode
// ============================================================================

static nh_switch_handle_t *hook_multi(uintptr_t target_addr, uintptr_t new_func,
                                      void **orig_func, size_t sym_size,
                                      int *out_err) {
  nh_switch_t *sw = find_switch(target_addr);

  if (sw != NULL) {
    // mode conflict check
    if (sw->hook_mode == NH_SWITCH_MODE_UNIQUE) {
      if (out_err) *out_err = NH_ERR_MODE_CONFLICT;
      return NULL;
    }
  }

  // create proxy
  nh_multi_proxy_t *proxy = calloc(1, sizeof(nh_multi_proxy_t));
  if (!proxy) { if (out_err) *out_err = NH_ERR_OOM; return NULL; }

  proxy->new_addr = new_func;
  proxy->orig_addr = (uintptr_t *)orig_func;

  if (sw == NULL) {
    // first hook on this address
    sw = create_switch(target_addr, new_func, orig_func, sym_size, out_err);
    if (!sw) { free(proxy); return NULL; }

    sw->hook_mode = NH_SWITCH_MODE_MULTI;
    // orig_func already set by create_switch (points to resume_addr)
    proxy->prev = NULL;
    proxy->next = NULL;
    sw->proxies_head = proxy;
    sw->proxies_tail = proxy;
  } else {
    // subsequent hook: append proxy to tail, relink chain
    // new proxy initially points to original function
    *(proxy->orig_addr) = sw->resume_addr;

    proxy->prev = sw->proxies_tail;
    proxy->next = NULL;

    if (sw->proxies_tail) {
      sw->proxies_tail->next = proxy;
      // previous tail's orig_addr now points to new proxy's function
      __atomic_store_n(sw->proxies_tail->orig_addr, new_func, __ATOMIC_RELEASE);
    }

    sw->proxies_tail = proxy;

    if (!sw->proxies_head) {
      sw->proxies_head = proxy;
    }
  }

  nh_switch_handle_t *handle = calloc(1, sizeof(nh_switch_handle_t));
  if (!handle) {
    // cleanup proxy from chain
    nh_multi_proxy_t *prev = proxy->prev;
    nh_multi_proxy_t *next = proxy->next;

    if (prev) {
      prev->next = next;
      // restore prev's orig_addr to point to next or resume
      uintptr_t target = next ? next->new_addr : sw->resume_addr;
      __atomic_store_n(prev->orig_addr, target, __ATOMIC_RELEASE);
    } else {
      sw->proxies_head = next;
    }
    if (next) {
      next->prev = prev;
    } else {
      sw->proxies_tail = prev;
    }
    free(proxy);

    // if this was the only proxy, destroy the switch
    if (!sw->proxies_head) {
      sw->hook_mode = NH_SWITCH_MODE_NONE;
      destroy_switch(sw);
    }
    if (out_err) *out_err = NH_ERR_OOM;
    return NULL;
  }

  handle->sw = sw;
  handle->mode = NH_MODE_MULTI;
  handle->new_func = new_func;

  return handle;
}

static int unhook_multi(nh_switch_handle_t *handle) {
  nh_switch_t *sw = handle->sw;
  uintptr_t func = handle->new_func;

  // find proxy by new_addr
  nh_multi_proxy_t *proxy = NULL;
  for (nh_multi_proxy_t *p = sw->proxies_head; p != NULL; p = p->next) {
    if (p->new_addr == func) { proxy = p; break; }
  }
  if (!proxy) { free(handle); return NH_ERR_NOT_HOOKED; }

  // relink chain
  nh_multi_proxy_t *prev = proxy->prev;
  nh_multi_proxy_t *next = proxy->next;

  if (prev) {
    prev->next = next;
    // prev's orig_addr skips over removed proxy
    uintptr_t target = next ? next->new_addr : sw->resume_addr;
    __atomic_store_n(prev->orig_addr, target, __ATOMIC_RELEASE);
  } else {
    // removing head — atomically redirect to new head without uninstall/reinstall
    sw->proxies_head = next;
    if (next) {
      int r = nh_hook_update_new_func(&sw->inst, next->new_addr);
      if (r != NH_OK) {
        NH_LOG_E("switch: update new_func after multi unhook failed: %d", r);
      }
    }
  }

  if (next) {
    next->prev = prev;
  } else {
    sw->proxies_tail = prev;
  }

  free(proxy);

  // if no more proxies, destroy switch
  if (!sw->proxies_head) {
    sw->hook_mode = NH_SWITCH_MODE_NONE;
    destroy_switch(sw);
  }

  free(handle);
  return NH_OK;
}

// ============================================================================
// SHARED mode
// ============================================================================

static nh_switch_handle_t *hook_shared(uintptr_t target_addr, uintptr_t new_func,
                                       void **orig_func, size_t sym_size,
                                       int *out_err) {
  nh_switch_t *sw = find_switch(target_addr);

  if (sw != NULL) {
    if (sw->hook_mode == NH_SWITCH_MODE_UNIQUE) {
      if (out_err) *out_err = NH_ERR_MODE_CONFLICT;
      return NULL;
    }

    // existing SHARED switch — just add proxy to hub
    if (sw->hub && nh_hub_has_proxy(sw->hub, new_func)) {
      if (out_err) *out_err = NH_ERR_DUP;
      return NULL;
    }

    int r = nh_hub_add_proxy(sw->hub, new_func);
    if (r != 0) { if (out_err) *out_err = r; return NULL; }

    if (orig_func) *orig_func = (void *)sw->resume_addr;

    nh_switch_handle_t *handle = calloc(1, sizeof(nh_switch_handle_t));
    if (!handle) {
      nh_hub_del_proxy(sw->hub, new_func);
      if (out_err) *out_err = NH_ERR_OOM;
      return NULL;
    }

    handle->sw = sw;
    handle->mode = NH_MODE_SHARED;
    handle->new_func = new_func;
    return handle;
  }

  // first SHARED hook on this address: create switch + hub
  sw = calloc(1, sizeof(nh_switch_t));
  if (!sw) { if (out_err) *out_err = NH_ERR_OOM; return NULL; }
  sw->target_addr = target_addr;
  sw->hook_mode = NH_SWITCH_MODE_NONE;

  // 1. Create hub with temporary orig_addr=0 (updated after hook install)
  nh_hub_t *hub = NULL;
  int r = nh_hub_create(&hub, 0);
  if (r != 0) { if (out_err) *out_err = r; free(sw); return NULL; }

  sw->hub = hub;

  // 2. Add the proxy function to hub
  r = nh_hub_add_proxy(hub, new_func);
  if (r != 0) {
    if (out_err) *out_err = r;
    nh_hub_destroy(hub);
    free(sw);
    return NULL;
  }

  // 3. Install instruction hook pointing to hub trampoline
  void *hook_orig = NULL;
  r = nh_hook_install(&sw->inst, target_addr, nh_hub_get_trampo(hub), &hook_orig, sym_size);
  if (r != NH_OK) {
    if (out_err) *out_err = r;
    nh_hub_destroy(hub);
    free(sw);
    return NULL;
  }

  // 4. Now we have the real enter trampoline — update hub's orig_addr
  sw->resume_addr = sw->inst.enter;
  nh_hub_set_orig_addr(hub, sw->resume_addr);

  sw->hook_mode = NH_SWITCH_MODE_SHARED;

  // add to global list
  sw->next = g_switches;
  g_switches = sw;

  if (orig_func) *orig_func = (void *)sw->resume_addr;

  nh_switch_handle_t *handle = calloc(1, sizeof(nh_switch_handle_t));
  if (!handle) {
    nh_hub_destroy(hub);
    sw->hub = NULL;
    sw->hook_mode = NH_SWITCH_MODE_NONE;
    destroy_switch(sw);
    if (out_err) *out_err = NH_ERR_OOM;
    return NULL;
  }

  handle->sw = sw;
  handle->mode = NH_MODE_SHARED;
  handle->new_func = new_func;

  return handle;
}

static int unhook_shared(nh_switch_handle_t *handle) {
  nh_switch_t *sw = handle->sw;

  int r = nh_hub_del_proxy(sw->hub, handle->new_func);
  if (r != 0) { free(handle); return r; }

  // if no more proxies, tear down everything
  if (nh_hub_get_proxy_count(sw->hub) == 0) {
    nh_hub_destroy(sw->hub);
    sw->hub = NULL;
    sw->hook_mode = NH_SWITCH_MODE_NONE;
    destroy_switch(sw);
  }

  free(handle);
  return NH_OK;
}

// ============================================================================
// Public API
// ============================================================================

nh_switch_handle_t *nh_switch_hook(uintptr_t target_addr, uintptr_t new_func,
                                   void **orig_func, int mode, size_t sym_size,
                                   int *out_errno) {
  pthread_mutex_lock(&g_switches_lock);

  nh_switch_handle_t *handle = NULL;

  // mode conflict pre-check: each address can only be in one mode
  nh_switch_t *existing = find_switch(target_addr);
  if (existing && existing->hook_mode != NH_SWITCH_MODE_NONE) {
    if (existing->hook_mode != mode) {
      pthread_mutex_unlock(&g_switches_lock);
      if (out_errno) *out_errno = NH_ERR_MODE_CONFLICT;
      return NULL;
    }
  }

  switch (mode) {
    case NH_MODE_UNIQUE:
      handle = hook_unique(target_addr, new_func, orig_func, sym_size, out_errno);
      break;
    case NH_MODE_MULTI:
      handle = hook_multi(target_addr, new_func, orig_func, sym_size, out_errno);
      break;
    case NH_MODE_SHARED:
      handle = hook_shared(target_addr, new_func, orig_func, sym_size, out_errno);
      break;
    default:
      if (out_errno) *out_errno = NH_ERR_INVALID_ARG;
      break;
  }

  if (handle) track_handle(handle);

  pthread_mutex_unlock(&g_switches_lock);
  return handle;
}

int nh_switch_unhook(nh_switch_handle_t *handle) {
  if (!handle) return NH_ERR_INVALID_ARG;

  pthread_mutex_lock(&g_switches_lock);

  // validate handle is still live
  if (!untrack_handle(handle)) {
    pthread_mutex_unlock(&g_switches_lock);
    return NH_ERR_NOT_HOOKED;
  }

  int r;
  switch (handle->mode) {
    case NH_MODE_UNIQUE:
      r = unhook_unique(handle);
      break;
    case NH_MODE_MULTI:
      r = unhook_multi(handle);
      break;
    case NH_MODE_SHARED:
      r = unhook_shared(handle);
      break;
    default:
      r = NH_ERR_INVALID_ARG;
      break;
  }

  pthread_mutex_unlock(&g_switches_lock);
  return r;
}
