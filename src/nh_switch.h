#ifndef NH_SWITCH_H
#define NH_SWITCH_H

#include <stddef.h>
#include <stdint.h>

// Opaque handle returned to user
typedef struct nh_switch_handle nh_switch_handle_t;

// Initialize the switch module (called once from newhook_init).
void nh_switch_init(void);

// Hook target_addr with new_func in the given mode.
// On success, *orig_func is set and a handle is returned.
// sym_size: size of target symbol (0 if unknown).
nh_switch_handle_t *nh_switch_hook(uintptr_t target_addr, uintptr_t new_func,
                                   void **orig_func, int mode, size_t sym_size);

// Unhook a previously installed hook.
int nh_switch_unhook(nh_switch_handle_t *handle);

#endif // NH_SWITCH_H
