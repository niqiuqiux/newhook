#ifndef NH_HOOK_H
#define NH_HOOK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// backup: max 4 instructions for non-island strategy (16 bytes)
// plus room for 2 extra if needed: 6 * 4 = 24 bytes
#define NH_HOOK_BACKUP_MAX  6

typedef struct {
  uintptr_t target_addr;                    // hooked target address
  uintptr_t new_func;                       // replacement function
  uintptr_t enter;                          // enter trampoline (calls original)
  uint32_t  backup[NH_HOOK_BACKUP_MAX];     // backed-up original instructions
  size_t    backup_len;                     // backup length in bytes
  uintptr_t island_exit;                    // island: target → new_func
  bool      with_island;                    // strategy A or B
  bool      hooked;                         // currently active
} nh_hook_t;

// Install a hook at target_addr, redirecting to new_func.
// On success, *orig_func is set to the enter trampoline address.
// IMPORTANT: *orig_func is written BEFORE the hook takes effect, so it is
// safe to call the original function from the hook callback immediately.
// sym_size: size of the target symbol (0 if unknown).
// Returns NH_OK on success, error code on failure.
int nh_hook_install(nh_hook_t *hook, uintptr_t target_addr, uintptr_t new_func,
                    void **orig_func, size_t sym_size);

// Remove a previously installed hook, restoring original instructions.
int nh_hook_uninstall(nh_hook_t *hook);

// Atomically update where the hook redirects to (without uninstall/reinstall).
// Only updates the .quad address in the jump sequence.
// Returns NH_OK on success.
int nh_hook_update_new_func(nh_hook_t *hook, uintptr_t new_func);

#endif // NH_HOOK_H
