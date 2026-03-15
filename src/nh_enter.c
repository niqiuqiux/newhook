#include "nh_enter.h"

#include "nh_trampo.h"

#define NH_ENTER_DELAY_SEC 10

static nh_trampo_mgr_t g_enter_mgr_island;
static nh_trampo_mgr_t g_enter_mgr_no_island;

void nh_enter_init(void) {
  nh_trampo_mgr_init(&g_enter_mgr_island, NH_ENTER_WITH_ISLAND_SIZE, NH_ENTER_DELAY_SEC);
  nh_trampo_mgr_init(&g_enter_mgr_no_island, NH_ENTER_WITHOUT_ISLAND_SIZE, NH_ENTER_DELAY_SEC);
}

uintptr_t nh_enter_alloc(bool with_island) {
  nh_trampo_mgr_t *mgr = with_island ? &g_enter_mgr_island : &g_enter_mgr_no_island;
  // Enter trampolines have no range constraint (they can be anywhere in address space)
  return nh_trampo_alloc(mgr, 0, 0);
}

void nh_enter_free(uintptr_t addr, bool with_island) {
  nh_trampo_mgr_t *mgr = with_island ? &g_enter_mgr_island : &g_enter_mgr_no_island;
  nh_trampo_free(mgr, addr);
}
