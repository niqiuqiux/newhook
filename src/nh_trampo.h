#ifndef NH_TRAMPO_H
#define NH_TRAMPO_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

// A memory page managed by the trampoline manager.
typedef struct nh_trampo_page {
  uintptr_t addr;       // page base address (mmap'd, RWX)
  size_t    page_size;  // actual page size
  size_t    count;      // number of chunks in this page
  uint32_t *flags;      // per-chunk: bit31=used, bits[30:0]=free_timestamp
  struct nh_trampo_page *next;
} nh_trampo_page_t;

// Trampoline memory manager.
// Manages fixed-size chunks of executable memory.
typedef struct {
  size_t           chunk_size;   // size of each chunk (e.g. 64, 256, 20)
  uint32_t         delay_sec;    // seconds to delay before reusing freed chunks
  nh_trampo_page_t *pages;       // linked list of managed pages
  pthread_mutex_t  lock;
} nh_trampo_mgr_t;

// Initialize a trampoline manager.
void nh_trampo_mgr_init(nh_trampo_mgr_t *mgr, size_t chunk_size, uint32_t delay_sec);

// Allocate a chunk. If range_low/range_high are non-zero, the allocated address
// must fall within [range_low, range_high].
// Returns chunk address, or 0 on failure.
uintptr_t nh_trampo_alloc(nh_trampo_mgr_t *mgr, uintptr_t range_low, uintptr_t range_high);

// Free a previously allocated chunk (marks for delayed reuse).
void nh_trampo_free(nh_trampo_mgr_t *mgr, uintptr_t addr);

#endif // NH_TRAMPO_H
