#ifndef NH_TASK_H
#define NH_TASK_H

#include <stddef.h>
#include <stdint.h>

// Opaque pending task handle (returned to user as void*)
typedef struct nh_task nh_task_t;

// Initialize task system: register dl_init callback with linker monitor.
// Must be called after nh_linker_init().
int nh_task_init(void);

// Create a pending task for a symbol that isn't loaded yet.
// Returns a task handle (also serves as the user's hook handle).
nh_task_t *nh_task_create(const char *lib_name, const char *sym_name,
                          uintptr_t new_func, void **orig_func, int mode);

// Cancel/destroy a pending task.
int nh_task_destroy(nh_task_t *task);

// Check if a handle is a pending task (vs a switch handle).
int nh_task_is_task(void *handle);

// Get the underlying switch handle if the task has been activated.
// Returns NULL if still pending.
void *nh_task_get_switch_handle(nh_task_t *task);

#endif // NH_TASK_H
