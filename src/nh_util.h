#ifndef NH_UTIL_H
#define NH_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// bit extraction: get bits [hi:lo] from val (inclusive, 0-based)
#define NH_BITS_GET_32(val, hi, lo) (((uint32_t)(val) >> (lo)) & ((1u << ((hi) - (lo) + 1)) - 1))
#define NH_BITS_GET_64(val, hi, lo) (((uint64_t)(val) >> (lo)) & ((UINT64_C(1) << ((hi) - (lo) + 1)) - 1))

// sign extension: extend 'bits'-wide value to full width
#define NH_SIGN_EXTEND_32(val, bits) \
  ((int32_t)((uint32_t)(val) << (32 - (bits))) >> (32 - (bits)))
#define NH_SIGN_EXTEND_64(val, bits) \
  ((int64_t)((uint64_t)(val) << (64 - (bits))) >> (64 - (bits)))

// alignment
#define NH_ALIGN_START(x, align) ((uintptr_t)(x) & ~((uintptr_t)(align) - 1))
#define NH_ALIGN_END(x, align)   NH_ALIGN_START((uintptr_t)(x) + (uintptr_t)(align) - 1, align)

// page helpers (runtime page size)
size_t    nh_util_get_page_size(void);
uintptr_t nh_util_page_start(uintptr_t addr);
uintptr_t nh_util_page_end(uintptr_t addr);

// memory protection
int nh_util_mprotect(uintptr_t addr, size_t len, int prot);

// instruction cache flush
void nh_util_flush_cache(uintptr_t addr, size_t len);

// atomic instruction write (4 / 8 / 16 bytes)
void nh_util_write_inst(uintptr_t addr, const void *data, size_t len);

// timestamp (seconds, monotonic)
uint32_t nh_util_get_timestamp(void);

// string basename match (e.g. "/system/lib64/libc.so" matches "libc.so")
bool nh_util_ends_with(const char *str, const char *suffix);
bool nh_util_match_lib_name(const char *pathname, const char *lib_name);

#endif // NH_UTIL_H
