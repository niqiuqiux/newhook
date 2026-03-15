#include "nh_island.h"

#include "nh_trampo.h"

#define NH_ISLAND_DELAY_SEC 3

static nh_trampo_mgr_t g_island_mgr;

void nh_island_init(void) {
  // Island chunks are 20 bytes, aligned to 4 bytes.
  nh_trampo_mgr_init(&g_island_mgr, NH_ISLAND_SIZE, NH_ISLAND_DELAY_SEC);
}

uintptr_t nh_island_alloc(uintptr_t target, uintptr_t range) {
  uintptr_t range_low = (target > range) ? (target - range) : 0;
  uintptr_t range_high = (target + range > target) ? (target + range) : UINTPTR_MAX;
  return nh_trampo_alloc(&g_island_mgr, range_low, range_high);
}

void nh_island_free(uintptr_t addr) {
  nh_trampo_free(&g_island_mgr, addr);
}
