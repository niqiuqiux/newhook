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
  // For 16-byte writes, we write the data portion first (bytes 8-15),
  // then the instruction portion (bytes 0-7) which activates the hook.
  if (len == 4) {
    __atomic_store_n((uint32_t *)addr, *(const uint32_t *)data, __ATOMIC_SEQ_CST);
  } else if (len == 8) {
    __atomic_store_n((uint64_t *)addr, *(const uint64_t *)data, __ATOMIC_SEQ_CST);
  } else if (len == 16) {
    // Write address data first (harmless if partially read by other threads)
    __atomic_store_n((uint64_t *)(addr + 8), *((const uint64_t *)data + 1), __ATOMIC_SEQ_CST);
    // Memory barrier
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    // Write instruction pair (LDR + BR) last to activate the hook
    __atomic_store_n((uint64_t *)addr, *(const uint64_t *)data, __ATOMIC_SEQ_CST);
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
