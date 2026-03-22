#include "nh_util.h"

#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

static size_t g_page_size = 0;

size_t nh_util_get_page_size(void) {
  if (__builtin_expect(g_page_size == 0, 0)) {
    g_page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (g_page_size == 0) g_page_size = 4096;
  }
  return g_page_size;
}

uintptr_t nh_util_page_start(uintptr_t addr) {
  size_t ps = nh_util_get_page_size();
  return addr & ~(ps - 1);
}

uintptr_t nh_util_page_end(uintptr_t addr) {
  size_t ps = nh_util_get_page_size();
  return (addr + ps - 1) & ~(ps - 1);
}

int nh_util_mprotect(uintptr_t addr, size_t len, int prot) {
  uintptr_t start = nh_util_page_start(addr);
  uintptr_t end = nh_util_page_end(addr + len);
  return mprotect((void *)start, end - start, prot);
}

void nh_util_flush_cache(uintptr_t addr, size_t len) {
  __builtin___clear_cache((void *)addr, (void *)(addr + len));
}

void nh_util_write_inst(uintptr_t addr, const void *data, size_t len) {
  // ARM64 guarantees atomic aligned 4-byte and 8-byte stores.
  // For multi-word writes, we write data/tail portions first, then the
  // instruction portion last to activate the hook atomically.
  if (len == 4) {
    __atomic_store_n((uint32_t *)addr, *(const uint32_t *)data, __ATOMIC_SEQ_CST);
  } else if (len == 8) {
    // Write bytes [4-7] first, then [0-3] to activate
    __atomic_store_n((uint32_t *)(addr + 4), *((const uint32_t *)data + 1), __ATOMIC_SEQ_CST);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    __atomic_store_n((uint32_t *)addr, *(const uint32_t *)data, __ATOMIC_SEQ_CST);
  } else if (len == 16) {
    // Write address data first (bytes 8-15, harmless if partially read)
    __atomic_store_n((uint64_t *)(addr + 8), *((const uint64_t *)data + 1), __ATOMIC_SEQ_CST);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    // Write instruction pair (LDR + BR) last to activate the hook
    __atomic_store_n((uint64_t *)addr, *(const uint64_t *)data, __ATOMIC_SEQ_CST);
  } else if (len == 20) {
    // BTI-aware 20-byte write: BTI c + LDR X17 + BR X17 + .quad addr
    // Write order: .quad (bytes 12-19) → LDR+BR (bytes 4-11) → BTI c (byte 0-3)
    __atomic_store_n((uint64_t *)(addr + 12), *((const uint64_t *)((const uint8_t *)data + 12)), __ATOMIC_SEQ_CST);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    __atomic_store_n((uint64_t *)(addr + 4), *((const uint64_t *)((const uint8_t *)data + 4)), __ATOMIC_SEQ_CST);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    __atomic_store_n((uint32_t *)addr, *(const uint32_t *)data, __ATOMIC_SEQ_CST);
  } else {
    // Fallback: byte-by-byte copy (shouldn't happen in normal use)
    memcpy((void *)addr, data, len);
  }
  __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

uint32_t nh_util_get_timestamp(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint32_t)ts.tv_sec;
}

bool nh_util_ends_with(const char *str, const char *suffix) {
  if (str == NULL || suffix == NULL) return false;
  size_t str_len = strlen(str);
  size_t suf_len = strlen(suffix);
  if (suf_len > str_len) return false;
  return strcmp(str + str_len - suf_len, suffix) == 0;
}

bool nh_util_match_lib_name(const char *pathname, const char *lib_name) {
  if (pathname == NULL) return false;
  if (lib_name == NULL) return true;  // NULL means match any

  // exact match
  if (strcmp(pathname, lib_name) == 0) return true;

  // basename match: check if pathname ends with /lib_name
  size_t plen = strlen(pathname);
  size_t llen = strlen(lib_name);
  if (llen >= plen) return strcmp(pathname, lib_name) == 0;
  if (pathname[plen - llen - 1] == '/') {
    return strcmp(pathname + plen - llen, lib_name) == 0;
  }

  return false;
}
