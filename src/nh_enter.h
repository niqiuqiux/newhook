#ifndef NH_ENTER_H
#define NH_ENTER_H

#include <stdbool.h>
#include <stdint.h>

#define NH_ENTER_WITH_ISLAND_SIZE     64
#define NH_ENTER_WITHOUT_ISLAND_SIZE  256

// Initialize enter trampoline managers. Called once during newhook_init().
void nh_enter_init(void);

// Allocate an enter trampoline.
// with_island: true = 64B (strategy A), false = 256B (strategy B)
// Returns trampoline address, or 0 on failure.
uintptr_t nh_enter_alloc(bool with_island);

// Free an enter trampoline (delayed reuse).
void nh_enter_free(uintptr_t addr, bool with_island);

#endif // NH_ENTER_H
