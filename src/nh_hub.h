#ifndef NH_HUB_H
#define NH_HUB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct nh_hub nh_hub_t;

// Create a hub for SHARED mode. Allocates trampoline in executable memory.
// orig_addr: the enter trampoline address (original function).
int nh_hub_create(nh_hub_t **out, uintptr_t orig_addr);

// Destroy hub and free all resources.
void nh_hub_destroy(nh_hub_t *hub);

// Get the hub trampoline address (instruction hook should jump here).
uintptr_t nh_hub_get_trampo(nh_hub_t *hub);

// Set the original function address (enter trampoline).
// Must be called before any proxy is invoked.
void nh_hub_set_orig_addr(nh_hub_t *hub, uintptr_t orig_addr);

// Add a proxy function to the hub. Returns 0 on success.
int nh_hub_add_proxy(nh_hub_t *hub, uintptr_t func);

// Remove (disable) a proxy function. Returns 0 on success.
int nh_hub_del_proxy(nh_hub_t *hub, uintptr_t func);

// Get the number of enabled proxies.
size_t nh_hub_get_proxy_count(nh_hub_t *hub);

// Check if a proxy function is already registered.
bool nh_hub_has_proxy(nh_hub_t *hub, uintptr_t func);

// ── Called from user hook functions (SHARED mode) ──

// Get the next function in the proxy chain (or original function).
void *nh_hub_get_prev_func(void *current_func);

// Pop the current stack frame. Call at end of hook with __builtin_return_address(0).
void nh_hub_pop_stack(void *return_address);

// Get the original return address saved by the hub trampoline.
void *nh_hub_get_return_address(void);

// Initialize hub TLS (called once from newhook_init).
void nh_hub_init(void);

#endif // NH_HUB_H
