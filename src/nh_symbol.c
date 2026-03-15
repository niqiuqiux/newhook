#include "nh_symbol.h"

#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <string.h>

#include "nh_log.h"
#include "nh_util.h"

// ============================================================
// Helper: resolve d_ptr from .dynamic entry
// ============================================================
// On Android, shared libraries have their .dynamic d_ptr values
// already relocated by the linker (absolute addresses). But the
// main executable (PIE) may have unrelocated values (virtual
// addresses relative to 0). We detect this by checking if d_ptr
// falls within the module's actual loaded address range.

static void compute_load_range(struct dl_phdr_info *info,
                               uintptr_t *out_min, uintptr_t *out_max) {
  uintptr_t lo = UINTPTR_MAX, hi = 0;
  for (size_t i = 0; i < info->dlpi_phnum; i++) {
    if (info->dlpi_phdr[i].p_type != PT_LOAD) continue;
    uintptr_t start = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
    uintptr_t end = start + info->dlpi_phdr[i].p_memsz;
    if (start < lo) lo = start;
    if (end > hi) hi = end;
  }
  *out_min = lo;
  *out_max = hi;
}

static uintptr_t resolve_dyn_ptr(uintptr_t d_ptr, uintptr_t load_bias,
                                 uintptr_t range_min, uintptr_t range_max) {
  // If d_ptr already falls within the module's loaded memory range,
  // it's been relocated by the dynamic linker — use as-is.
  if (d_ptr >= range_min && d_ptr < range_max) {
    return d_ptr;
  }
  // Otherwise it's an unrelocated virtual address — add load bias.
  return d_ptr + load_bias;
}

// ============================================================
// GNU hash: compute symbol count from DT_GNU_HASH
// ============================================================

static size_t gnu_hash_symbol_count(const void *gnu_hash_ptr) {
  const uint32_t *gnu_hash = (const uint32_t *)gnu_hash_ptr;
  uint32_t nbuckets = gnu_hash[0];
  uint32_t symoffset = gnu_hash[1];
  uint32_t bloom_size = gnu_hash[2];
  // uint32_t bloom_shift = gnu_hash[3];

  // skip: bloom filter (bloom_size * sizeof(uintptr_t) bytes)
  const uint32_t *buckets =
      (const uint32_t *)((const uint8_t *)gnu_hash + 16 + bloom_size * sizeof(uintptr_t));
  const uint32_t *chains = buckets + nbuckets;

  // Find the max bucket value (highest non-empty bucket index)
  uint32_t max_sym = 0;
  for (uint32_t i = 0; i < nbuckets; i++) {
    if (buckets[i] > max_sym) max_sym = buckets[i];
  }
  if (max_sym == 0) return symoffset;  // all buckets empty

  // Walk the chain from max_sym until we hit the end marker (bit 0 set)
  uint32_t idx = max_sym - symoffset;
  while ((chains[idx] & 1) == 0) {
    idx++;
    max_sym++;
  }

  return max_sym + 1;
}

// ============================================================
// Callback context for dl_iterate_phdr
// ============================================================

typedef struct {
  const char *lib_name;
  const char *sym_name;
  nh_symbol_info_t *info;
} nh_sym_ctx_t;

static int sym_find_callback(struct dl_phdr_info *phdr_info, size_t size, void *data) {
  (void)size;
  nh_sym_ctx_t *ctx = (nh_sym_ctx_t *)data;

  // Match library name
  if (ctx->lib_name != NULL) {
    if (phdr_info->dlpi_name == NULL || phdr_info->dlpi_name[0] == '\0') return 0;
    if (!nh_util_match_lib_name(phdr_info->dlpi_name, ctx->lib_name)) return 0;
  }

  // Find PT_DYNAMIC segment
  const ElfW(Dyn) *dyn = NULL;
  for (size_t i = 0; i < phdr_info->dlpi_phnum; i++) {
    if (phdr_info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
      dyn = (const ElfW(Dyn) *)(phdr_info->dlpi_addr + phdr_info->dlpi_phdr[i].p_vaddr);
      break;
    }
  }
  if (dyn == NULL) return 0;

  // Extract symbol table, string table, and symbol count from .dynamic
  const ElfW(Sym) *symtab = NULL;
  const char *strtab = NULL;
  size_t sym_count = 0;
  const void *gnu_hash = NULL;

  uintptr_t load_bias = phdr_info->dlpi_addr;
  uintptr_t range_min, range_max;
  compute_load_range(phdr_info, &range_min, &range_max);

  for (const ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
    switch (d->d_tag) {
      case DT_SYMTAB:
        symtab = (const ElfW(Sym) *)resolve_dyn_ptr(d->d_un.d_ptr, load_bias, range_min, range_max);
        break;
      case DT_STRTAB:
        strtab = (const char *)resolve_dyn_ptr(d->d_un.d_ptr, load_bias, range_min, range_max);
        break;
      case DT_HASH: {
        // Traditional ELF hash: { nbucket, nchain, ... }
        const uint32_t *hash = (const uint32_t *)resolve_dyn_ptr(d->d_un.d_ptr, load_bias, range_min, range_max);
        size_t nchain = hash[1];
        if (sym_count == 0) sym_count = nchain;
        break;
      }
      case DT_GNU_HASH:
        gnu_hash = (const void *)resolve_dyn_ptr(d->d_un.d_ptr, load_bias, range_min, range_max);
        break;
    }
  }

  // Prefer GNU hash for symbol count (more accurate on modern Android)
  if (gnu_hash != NULL) {
    sym_count = gnu_hash_symbol_count(gnu_hash);
  }

  if (symtab == NULL || strtab == NULL || sym_count == 0) return 0;

  // Search .dynsym for the target symbol
  for (size_t i = 0; i < sym_count; i++) {
    const ElfW(Sym) *sym = &symtab[i];

    // Only look at defined function/object symbols
    if (sym->st_shndx == SHN_UNDEF) continue;
    uint8_t sym_type = ELF64_ST_TYPE(sym->st_info);
    if (sym_type != STT_FUNC && sym_type != STT_OBJECT) continue;

    const char *name = strtab + sym->st_name;
    if (strcmp(name, ctx->sym_name) == 0) {
      ctx->info->addr = (uintptr_t)(phdr_info->dlpi_addr + sym->st_value);
      ctx->info->size = (size_t)sym->st_size;
      ctx->info->found = true;
      NH_LOG_D("symbol: found %s at %p (size=%zu) in %s",
               ctx->sym_name, (void *)ctx->info->addr, ctx->info->size,
               phdr_info->dlpi_name ? phdr_info->dlpi_name : "(null)");
      return 1;  // stop iteration
    }
  }

  // If lib_name was specified but symbol not found in this lib, stop
  if (ctx->lib_name != NULL) return 1;

  return 0;  // continue iteration
}

int nh_symbol_find(const char *lib_name, const char *sym_name, nh_symbol_info_t *info) {
  if (sym_name == NULL || info == NULL) return -1;

  memset(info, 0, sizeof(*info));

  nh_sym_ctx_t ctx = {
    .lib_name = lib_name,
    .sym_name = sym_name,
    .info = info,
  };

  dl_iterate_phdr(sym_find_callback, &ctx);

  if (!info->found) {
    NH_LOG_W("symbol: %s not found in %s", sym_name, lib_name ? lib_name : "(all)");
    return -1;
  }
  return 0;
}

// ============================================================
// Reverse lookup by address
// ============================================================

typedef struct {
  uintptr_t addr;
  nh_symbol_info_t *info;
} nh_addr_ctx_t;

static int addr_find_callback(struct dl_phdr_info *phdr_info, size_t size, void *data) {
  (void)size;
  nh_addr_ctx_t *ctx = (nh_addr_ctx_t *)data;

  // Check if addr is within this ELF's PT_LOAD segments
  bool in_elf = false;
  for (size_t i = 0; i < phdr_info->dlpi_phnum; i++) {
    if (phdr_info->dlpi_phdr[i].p_type != PT_LOAD) continue;
    uintptr_t seg_start = phdr_info->dlpi_addr + phdr_info->dlpi_phdr[i].p_vaddr;
    uintptr_t seg_end = seg_start + phdr_info->dlpi_phdr[i].p_memsz;
    if (ctx->addr >= seg_start && ctx->addr < seg_end) {
      in_elf = true;
      break;
    }
  }
  if (!in_elf) return 0;

  // Find PT_DYNAMIC and extract symtab
  const ElfW(Dyn) *dyn = NULL;
  for (size_t i = 0; i < phdr_info->dlpi_phnum; i++) {
    if (phdr_info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
      dyn = (const ElfW(Dyn) *)(phdr_info->dlpi_addr + phdr_info->dlpi_phdr[i].p_vaddr);
      break;
    }
  }
  if (dyn == NULL) return 1;

  const ElfW(Sym) *symtab = NULL;
  const char *strtab = NULL;
  size_t sym_count = 0;
  const void *gnu_hash = NULL;

  uintptr_t load_bias = phdr_info->dlpi_addr;
  uintptr_t range_min, range_max;
  compute_load_range(phdr_info, &range_min, &range_max);

  for (const ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
    switch (d->d_tag) {
      case DT_SYMTAB:  symtab = (const ElfW(Sym) *)resolve_dyn_ptr(d->d_un.d_ptr, load_bias, range_min, range_max); break;
      case DT_STRTAB:  strtab = (const char *)resolve_dyn_ptr(d->d_un.d_ptr, load_bias, range_min, range_max); break;
      case DT_HASH: {
        const uint32_t *hash = (const uint32_t *)resolve_dyn_ptr(d->d_un.d_ptr, load_bias, range_min, range_max);
        if (sym_count == 0) sym_count = hash[1];
        break;
      }
      case DT_GNU_HASH: gnu_hash = (const void *)resolve_dyn_ptr(d->d_un.d_ptr, load_bias, range_min, range_max); break;
    }
  }
  if (gnu_hash != NULL) sym_count = gnu_hash_symbol_count(gnu_hash);
  if (symtab == NULL || strtab == NULL || sym_count == 0) return 1;

  // Find the symbol whose range contains ctx->addr
  for (size_t i = 0; i < sym_count; i++) {
    const ElfW(Sym) *sym = &symtab[i];
    if (sym->st_shndx == SHN_UNDEF || sym->st_size == 0) continue;

    uintptr_t sym_addr = phdr_info->dlpi_addr + sym->st_value;
    if (ctx->addr >= sym_addr && ctx->addr < sym_addr + sym->st_size) {
      ctx->info->addr = sym_addr;
      ctx->info->size = (size_t)sym->st_size;
      ctx->info->found = true;
      return 1;
    }
  }

  // Symbol not found in .dynsym, but we know which ELF it's in.
  // Use dladdr as fallback (doesn't give size, but gives address).
  Dl_info dl;
  if (dladdr((void *)ctx->addr, &dl) != 0 && dl.dli_saddr != NULL) {
    ctx->info->addr = (uintptr_t)dl.dli_saddr;
    ctx->info->size = 0;  // dladdr doesn't provide size
    ctx->info->found = true;
  }
  return 1;
}

int nh_symbol_find_by_addr(uintptr_t addr, nh_symbol_info_t *info) {
  if (addr == 0 || info == NULL) return -1;

  memset(info, 0, sizeof(*info));

  nh_addr_ctx_t ctx = {
    .addr = addr,
    .info = info,
  };

  dl_iterate_phdr(addr_find_callback, &ctx);

  return info->found ? 0 : -1;
}
