#ifndef NH_SYMBOL_H
#define NH_SYMBOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  uintptr_t addr;   // symbol address (load_bias + st_value)
  size_t    size;   // symbol size (st_size), 0 if unknown
  bool      found;
} nh_symbol_info_t;

// Find a symbol by library name and symbol name.
// lib_name: library basename (e.g. "libc.so"), NULL to search all loaded ELFs.
// sym_name: symbol name to find.
// Returns 0 on success, -1 on failure.
int nh_symbol_find(const char *lib_name, const char *sym_name, nh_symbol_info_t *info);

// Reverse-lookup: find symbol info for a given address.
// Uses dladdr() + .dynsym scan for size information.
// Returns 0 on success, -1 on failure.
int nh_symbol_find_by_addr(uintptr_t addr, nh_symbol_info_t *info);

#endif // NH_SYMBOL_H
