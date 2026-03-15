#include "nh_trampo.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "nh_log.h"
#include "nh_util.h"

void nh_trampo_mgr_init(nh_trampo_mgr_t *mgr, size_t chunk_size, uint32_t delay_sec) {
  mgr->chunk_size = NH_ALIGN_END(chunk_size, 4);
  mgr->delay_sec = delay_sec;
  mgr->pages = NULL;
  pthread_mutex_init(&mgr->lock, NULL);
}

// Try to allocate a chunk from an existing page.
static uintptr_t try_alloc_from_page(nh_trampo_page_t *page, size_t chunk_size,
                                     uintptr_t range_low, uintptr_t range_high,
                                     uint32_t now, uint32_t delay_sec) {
  for (size_t i = 0; i < page->count; i++) {
    uintptr_t addr = page->addr + chunk_size * i;

    // range check
    if (range_low != 0 && addr < range_low) continue;
    if (range_high != 0 && addr > range_high) continue;

    // check if used
    uint32_t flag = page->flags[i];
    if (flag >> 31) continue;  // in use

    // check timestamp delay
    uint32_t ts = flag & 0x7FFFFFFF;
    if (ts != 0 && (now <= ts || now - ts <= delay_sec)) continue;

    // mark as used
    page->flags[i] = 0x80000000;
    return addr;
  }
  return 0;
}

// Parse /proc/self/maps to find a free gap within [range_low, range_high].
// Returns a suitable address to mmap, or 0 if none found.
static uintptr_t find_free_addr_in_range(uintptr_t range_low, uintptr_t range_high, size_t size) {
  FILE *fp = fopen("/proc/self/maps", "r");
  if (fp == NULL) return 0;

  uintptr_t prev_end = range_low;
  uintptr_t result = 0;
  char line[512];

  while (fgets(line, sizeof(line), fp) != NULL) {
    uintptr_t start, end;
    if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &start, &end) != 2) continue;

    if (start > range_high) break;

    // Check gap between prev_end and start
    if (start > prev_end) {
      uintptr_t gap_start = NH_ALIGN_END(prev_end, nh_util_get_page_size());
      uintptr_t gap_end = NH_ALIGN_START(start, nh_util_get_page_size());
      if (gap_start >= range_low && gap_end <= range_high + 1 && gap_end - gap_start >= size) {
        result = gap_start;
        break;
      }
    }
    if (end > prev_end) prev_end = end;
  }
  fclose(fp);
  return result;
}

// Allocate a new page and add it to the manager.
static nh_trampo_page_t *alloc_new_page(nh_trampo_mgr_t *mgr,
                                         uintptr_t range_low, uintptr_t range_high) {
  size_t page_size = nh_util_get_page_size();
  void *addr = MAP_FAILED;

  if (range_low != 0 || range_high != 0) {
    // Range-constrained: find a free address in the specified range
    uintptr_t hint = find_free_addr_in_range(
        range_low != 0 ? range_low : 0,
        range_high != 0 ? range_high : UINTPTR_MAX,
        page_size);
    if (hint != 0) {
      addr = mmap((void *)hint, page_size,
                  PROT_READ | PROT_WRITE | PROT_EXEC,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      // Verify the returned address is in range
      if (addr != MAP_FAILED) {
        uintptr_t a = (uintptr_t)addr;
        if ((range_low != 0 && a < range_low) || (range_high != 0 && a > range_high)) {
          munmap(addr, page_size);
          addr = MAP_FAILED;
        }
      }
    }
  } else {
    // No range constraint
    addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  }

  if (addr == MAP_FAILED) return NULL;

  size_t count = page_size / mgr->chunk_size;
  nh_trampo_page_t *page = calloc(1, sizeof(nh_trampo_page_t));
  if (page == NULL) {
    munmap(addr, page_size);
    return NULL;
  }
  page->flags = calloc(count, sizeof(uint32_t));
  if (page->flags == NULL) {
    munmap(addr, page_size);
    free(page);
    return NULL;
  }

  page->addr = (uintptr_t)addr;
  page->page_size = page_size;
  page->count = count;
  page->next = mgr->pages;
  mgr->pages = page;

  NH_LOG_D("trampo: new page %p, chunk_size=%zu, count=%zu", addr, mgr->chunk_size, count);
  return page;
}

uintptr_t nh_trampo_alloc(nh_trampo_mgr_t *mgr, uintptr_t range_low, uintptr_t range_high) {
  pthread_mutex_lock(&mgr->lock);

  uint32_t now = nh_util_get_timestamp();
  uintptr_t result = 0;

  // Try existing pages first
  for (nh_trampo_page_t *p = mgr->pages; p != NULL; p = p->next) {
    result = try_alloc_from_page(p, mgr->chunk_size, range_low, range_high, now, mgr->delay_sec);
    if (result != 0) goto end;
  }

  // Allocate a new page
  nh_trampo_page_t *new_page = alloc_new_page(mgr, range_low, range_high);
  if (new_page != NULL) {
    result = try_alloc_from_page(new_page, mgr->chunk_size, range_low, range_high, now, mgr->delay_sec);
  }

end:
  pthread_mutex_unlock(&mgr->lock);
  return result;
}

void nh_trampo_free(nh_trampo_mgr_t *mgr, uintptr_t addr) {
  if (addr == 0) return;

  pthread_mutex_lock(&mgr->lock);

  uint32_t now = nh_util_get_timestamp();
  for (nh_trampo_page_t *p = mgr->pages; p != NULL; p = p->next) {
    if (addr >= p->addr && addr < p->addr + p->page_size) {
      size_t idx = (addr - p->addr) / mgr->chunk_size;
      if (idx < p->count) {
        // Clear used bit, set timestamp for delayed reuse
        p->flags[idx] = now & 0x7FFFFFFF;
        NH_LOG_D("trampo: free %p (page %p, idx=%zu)", (void *)addr, (void *)p->addr, idx);
      }
      break;
    }
  }

  pthread_mutex_unlock(&mgr->lock);
}
