#ifndef NH_ISLAND_H
#define NH_ISLAND_H

#include <stddef.h>
#include <stdint.h>

// Island size: LDR X17, [PC, #8]; BR X17; .quad addr = 4+4+8 = 16 bytes
// Rounded up to 20 for alignment margin.
#define NH_ISLAND_SIZE  20

// Initialize island manager. Called once during newhook_init().
void nh_island_init(void);

// Allocate an island within [target - range, target + range].
// Returns island address, or 0 on failure.
uintptr_t nh_island_alloc(uintptr_t target, uintptr_t range);

// Free an island (delayed reuse).
void nh_island_free(uintptr_t addr);

#endif // NH_ISLAND_H
