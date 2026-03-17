#ifndef NH_SOINFO_H
#define NH_SOINFO_H

#include <elf.h>
#include <link.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Hardcoded soinfo field offsets for ARM64 (LP64).
// Verified on Android 16 API 36 via soinfo_parse + soinfo_calc (offsetof).
//
// struct soinfo {
//   [  0] const ElfW(Phdr)* phdr;
//   [  8] size_t phnum;
//   ...
//   [208] link_map link_map_head;   // l_addr (== load_bias)
//   [216]   char* l_name;
//   [224]   ElfW(Dyn)* l_ld;
//   [232]   link_map* l_next;
//   [240]   link_map* l_prev;
//   [248] bool constructors_called;
//   [256] ElfW(Addr) load_bias;
//   ...
// };

#define NH_SOINFO_OFFSET_PHDR                 0
#define NH_SOINFO_OFFSET_PHNUM                8
#define NH_SOINFO_OFFSET_LINK_MAP_L_ADDR      208
#define NH_SOINFO_OFFSET_LINK_MAP_L_NAME      216
#define NH_SOINFO_OFFSET_CONSTRUCTORS_CALLED  248
#define NH_SOINFO_OFFSET_LOAD_BIAS            256

// Convert soinfo pointer to dl_phdr_info using hardcoded offsets.
// This is equivalent to shadowhook's sh_linker_soinfo_to_dlinfo().
static inline void nh_soinfo_to_dlinfo(void *soinfo, struct dl_phdr_info *out) {
  uintptr_t si = (uintptr_t)soinfo;
  out->dlpi_addr = *((ElfW(Addr) *)(si + NH_SOINFO_OFFSET_LINK_MAP_L_ADDR));
  out->dlpi_name = *((const char **)(si + NH_SOINFO_OFFSET_LINK_MAP_L_NAME));
  out->dlpi_phdr = *((const ElfW(Phdr) **)(si + NH_SOINFO_OFFSET_PHDR));
  out->dlpi_phnum = (ElfW(Half))(*((size_t *)(si + NH_SOINFO_OFFSET_PHNUM)));
}

// Check if soinfo's constructors have NOT been called yet (still loading).
static inline bool nh_soinfo_is_loading(void *soinfo) {
  return *((int *)((uintptr_t)soinfo + NH_SOINFO_OFFSET_CONSTRUCTORS_CALLED)) == 0;
}

#endif // NH_SOINFO_H
