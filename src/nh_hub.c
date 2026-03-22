#include "nh_hub.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "newhook.h"
#include "nh_log.h"
#include "nh_trampo.h"

// ============================================================================
// Constants
// ============================================================================

#define NH_HUB_STACK_FRAME_MAX  16
#define NH_HUB_THREAD_MAX       512

// ============================================================================
// Proxy: singly-linked list of hook functions
// ============================================================================

typedef struct nh_hub_proxy {
  uintptr_t func;
  bool enabled;
  struct nh_hub_proxy *next;
} nh_hub_proxy_t;

// ============================================================================
// Per-thread stack frame
// ============================================================================

typedef struct {
  nh_hub_proxy_t *proxies;      // snapshot of proxy list head at call time
  uintptr_t orig_addr;          // original function address
  void *return_address;         // caller's return address
} nh_hub_frame_t;

typedef struct {
  size_t frames_cnt;
  nh_hub_frame_t frames[NH_HUB_STACK_FRAME_MAX];
} nh_hub_stack_t;

// ============================================================================
// Hub structure
// ============================================================================

struct nh_hub {
  nh_hub_proxy_t *proxies;
  size_t proxies_cnt;
  uintptr_t orig_addr;          // enter trampoline (original function)
  uintptr_t trampo;             // hub trampoline address
  size_t trampo_size;
};

// ============================================================================
// TLS for per-thread stack
// ============================================================================

static pthread_key_t g_tls_key;
static bool g_tls_inited = false;

// Stack cache: pre-allocated stacks for fast reuse
static nh_hub_stack_t *g_stack_cache[NH_HUB_THREAD_MAX];
static size_t g_stack_cache_cnt = 0;
static pthread_mutex_t g_stack_cache_lock = PTHREAD_MUTEX_INITIALIZER;

static void tls_destructor(void *ptr) {
  if (!ptr) return;
  nh_hub_stack_t *stack = (nh_hub_stack_t *)ptr;

  // return to cache
  pthread_mutex_lock(&g_stack_cache_lock);
  if (g_stack_cache_cnt < NH_HUB_THREAD_MAX) {
    memset(stack, 0, sizeof(nh_hub_stack_t));
    g_stack_cache[g_stack_cache_cnt++] = stack;
    stack = NULL;
  }
  pthread_mutex_unlock(&g_stack_cache_lock);

  if (stack) free(stack);
}

void nh_hub_init(void) {
  if (g_tls_inited) return;
  pthread_key_create(&g_tls_key, tls_destructor);
  g_tls_inited = true;
}

static nh_hub_stack_t *get_stack(void) {
  nh_hub_stack_t *stack = (nh_hub_stack_t *)pthread_getspecific(g_tls_key);
  if (stack) return stack;

  // try cache first
  pthread_mutex_lock(&g_stack_cache_lock);
  if (g_stack_cache_cnt > 0) {
    stack = g_stack_cache[--g_stack_cache_cnt];
  }
  pthread_mutex_unlock(&g_stack_cache_lock);

  if (!stack) {
    stack = calloc(1, sizeof(nh_hub_stack_t));
    if (!stack) return NULL;
  }

  pthread_setspecific(g_tls_key, stack);
  return stack;
}

// ============================================================================
// Hub trampoline (ARM64)
//
// The trampoline is a small piece of executable code that:
//   1. Saves all argument registers (x0-x8, q0-q7) and LR
//   2. Calls nh_hub_push_stack(hub_ptr, saved_lr) -> returns proxy func addr
//   3. Restores all registers
//   4. Branches to the returned proxy function
//
// Layout in memory:
//   [code]  (instructions)
//   [data]  .quad nh_hub_push_stack_addr
//   [data]  .quad hub_ptr
// ============================================================================

// This function is called from the trampoline. NOT static — address taken.
uintptr_t nh_hub_push_stack_impl(nh_hub_t *hub, void *return_address) {
  nh_hub_stack_t *stack = get_stack();
  if (!stack || stack->frames_cnt >= NH_HUB_STACK_FRAME_MAX) {
    NH_LOG_E("hub: stack overflow or alloc failed");
    return hub->orig_addr;
  }

  // check for recursive call (same orig_addr already on stack)
  for (size_t i = 0; i < stack->frames_cnt; i++) {
    if (stack->frames[i].orig_addr == hub->orig_addr) {
      // recursive — skip to original
      return hub->orig_addr;
    }
  }

  // snapshot proxy list once for consistency
  nh_hub_proxy_t *proxies_snap = __atomic_load_n(&hub->proxies, __ATOMIC_ACQUIRE);

  // find first enabled proxy
  nh_hub_proxy_t *first = NULL;
  for (nh_hub_proxy_t *p = proxies_snap; p; p = p->next) {
    if (__atomic_load_n(&p->enabled, __ATOMIC_ACQUIRE)) {
      first = p;
      break;
    }
  }

  if (!first) return hub->orig_addr;

  // push frame using the same snapshot
  nh_hub_frame_t *frame = &stack->frames[stack->frames_cnt++];
  frame->proxies = proxies_snap;
  frame->orig_addr = hub->orig_addr;
  frame->return_address = return_address;

  return first->func;
}

// ARM64 trampoline template (defined in nh_hub_trampo.S)
extern void nh_hub_trampo_template(void);
extern void nh_hub_trampo_template_data(void);

static nh_trampo_mgr_t g_hub_trampo_mgr;
static bool g_hub_trampo_mgr_inited = false;
static size_t g_hub_trampo_code_size = 0;
static size_t g_hub_trampo_data_size = sizeof(void *) + sizeof(void *);  // 16 bytes

static int alloc_trampo(nh_hub_t *hub) {
  if (!g_hub_trampo_mgr_inited) {
    g_hub_trampo_code_size = (uintptr_t)&nh_hub_trampo_template_data -
                             (uintptr_t)&nh_hub_trampo_template;
    size_t trampo_total = g_hub_trampo_code_size + g_hub_trampo_data_size;
    nh_trampo_mgr_init(&g_hub_trampo_mgr, trampo_total, 10);
    g_hub_trampo_mgr_inited = true;
    NH_LOG_I("hub: trampo template code_size=%zu, total=%zu", g_hub_trampo_code_size, trampo_total);
  }

  size_t trampo_total = g_hub_trampo_code_size + g_hub_trampo_data_size;
  uintptr_t addr = nh_trampo_alloc(&g_hub_trampo_mgr, 0, 0);
  if (addr == 0) return NH_ERR_OOM;

  // Copy code template from assembly
  memcpy((void *)addr, (void *)&nh_hub_trampo_template, g_hub_trampo_code_size);

  // Patch data section (immediately after code)
  void **data = (void **)(addr + g_hub_trampo_code_size);
  data[0] = (void *)nh_hub_push_stack_impl;  // .L_push_stack
  data[1] = (void *)hub;                     // .L_hub_ptr

  // Flush icache
  __builtin___clear_cache((void *)addr, (void *)(addr + trampo_total));

  hub->trampo = addr;
  hub->trampo_size = trampo_total;
  return 0;
}

// ============================================================================
// Public API
// ============================================================================

int nh_hub_create(nh_hub_t **out, uintptr_t orig_addr) {
  nh_hub_t *hub = calloc(1, sizeof(nh_hub_t));
  if (!hub) return NH_ERR_OOM;

  hub->orig_addr = orig_addr;

  int r = alloc_trampo(hub);
  if (r != 0) {
    free(hub);
    return r;
  }

  NH_LOG_I("hub: created, trampo=%p, orig=%p", (void *)hub->trampo, (void *)orig_addr);
  *out = hub;
  return 0;
}

void nh_hub_set_orig_addr(nh_hub_t *hub, uintptr_t orig_addr) {
  hub->orig_addr = orig_addr;
}

void nh_hub_destroy(nh_hub_t *hub) {
  if (!hub) return;

  // free all proxies
  nh_hub_proxy_t *p = hub->proxies;
  while (p) {
    nh_hub_proxy_t *next = p->next;
    free(p);
    p = next;
  }

  // free trampoline (delayed via trampo manager)
  if (hub->trampo) {
    nh_trampo_free(&g_hub_trampo_mgr, hub->trampo);
  }

  free(hub);
}

uintptr_t nh_hub_get_trampo(nh_hub_t *hub) {
  return hub->trampo;
}

int nh_hub_add_proxy(nh_hub_t *hub, uintptr_t func) {
  // check for duplicate
  for (nh_hub_proxy_t *p = hub->proxies; p; p = p->next) {
    if (p->func == func) {
      if (__atomic_load_n(&p->enabled, __ATOMIC_ACQUIRE)) {
        return NH_ERR_DUP;
      }
      // re-enable disabled proxy
      __atomic_store_n(&p->enabled, true, __ATOMIC_RELEASE);
      hub->proxies_cnt++;
      return 0;
    }
  }

  nh_hub_proxy_t *proxy = calloc(1, sizeof(nh_hub_proxy_t));
  if (!proxy) return NH_ERR_OOM;

  proxy->func = func;
  proxy->enabled = true;

  // insert at head (atomic for readers)
  proxy->next = hub->proxies;
  __atomic_store_n(&hub->proxies, proxy, __ATOMIC_RELEASE);
  hub->proxies_cnt++;

  return 0;
}

int nh_hub_del_proxy(nh_hub_t *hub, uintptr_t func) {
  for (nh_hub_proxy_t *p = hub->proxies; p; p = p->next) {
    if (p->func == func && __atomic_load_n(&p->enabled, __ATOMIC_ACQUIRE)) {
      __atomic_store_n(&p->enabled, false, __ATOMIC_RELEASE);
      hub->proxies_cnt--;
      return 0;
    }
  }
  return NH_ERR_NOT_HOOKED;
}

size_t nh_hub_get_proxy_count(nh_hub_t *hub) {
  return hub->proxies_cnt;
}

bool nh_hub_has_proxy(nh_hub_t *hub, uintptr_t func) {
  for (nh_hub_proxy_t *p = hub->proxies; p; p = p->next) {
    if (p->func == func && __atomic_load_n(&p->enabled, __ATOMIC_ACQUIRE))
      return true;
  }
  return false;
}

// ============================================================================
// SHARED mode helpers (called from user hook functions)
// ============================================================================

void *nh_hub_get_prev_func(void *current_func) {
  if (!g_tls_inited) return NULL;

  nh_hub_stack_t *stack = (nh_hub_stack_t *)pthread_getspecific(g_tls_key);
  if (!stack || stack->frames_cnt == 0) return NULL;

  nh_hub_frame_t *frame = &stack->frames[stack->frames_cnt - 1];

  // walk proxy list from current func, find next enabled
  bool found_current = false;
  for (nh_hub_proxy_t *p = frame->proxies; p; p = p->next) {
    if (!__atomic_load_n(&p->enabled, __ATOMIC_ACQUIRE)) continue;
    if (found_current) return (void *)p->func;
    if (p->func == (uintptr_t)current_func) found_current = true;
  }

  // no more proxies, return original function
  return (void *)frame->orig_addr;
}

void nh_hub_pop_stack(void *return_address) {
  if (!g_tls_inited) return;

  nh_hub_stack_t *stack = (nh_hub_stack_t *)pthread_getspecific(g_tls_key);
  if (!stack || stack->frames_cnt == 0) return;

  nh_hub_frame_t *frame = &stack->frames[stack->frames_cnt - 1];
  if (frame->return_address == return_address || return_address == NULL) {
    stack->frames_cnt--;
  }
}

void *nh_hub_get_return_address(void) {
  if (!g_tls_inited) return NULL;

  nh_hub_stack_t *stack = (nh_hub_stack_t *)pthread_getspecific(g_tls_key);
  if (!stack || stack->frames_cnt == 0) return NULL;

  return stack->frames[stack->frames_cnt - 1].return_address;
}
