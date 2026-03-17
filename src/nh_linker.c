#include "nh_linker.h"

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include "newhook.h"
#include "nh_log.h"
#include "nh_soinfo.h"

// ============================================================================
// Linker symbol names
// ============================================================================

#define SYM_CALL_CTORS_M "__dl__ZN6soinfo17call_constructorsEv"
#define SYM_CALL_CTORS_L "__dl__ZN6soinfo16CallConstructorsEv"
#define SYM_CALL_DTORS_M "__dl__ZN6soinfo16call_destructorsEv"
#define SYM_CALL_DTORS_L "__dl__ZN6soinfo15CallDestructorsEv"

// ============================================================================
// Callback list entry
// ============================================================================

typedef struct nh_dl_cb {
  nh_dl_info_cb_t pre;
  nh_dl_info_cb_t post;
  void *data;
  struct nh_dl_cb *next;
} nh_dl_cb_t;

// ============================================================================
// Global state
// ============================================================================

static nh_dl_cb_t *g_init_cbs = NULL;
static pthread_rwlock_t g_init_cbs_lock = PTHREAD_RWLOCK_INITIALIZER;

static nh_dl_cb_t *g_fini_cbs = NULL;
static pthread_rwlock_t g_fini_cbs_lock = PTHREAD_RWLOCK_INITIALIZER;

static void *g_hook_ctors = NULL;
static void *g_hook_dtors = NULL;
static bool g_linker_inited = false;

// ============================================================================
// Original function pointers (filled by newhook)
// ============================================================================

static void (*g_orig_call_ctors)(void *) = NULL;
static void (*g_orig_call_dtors)(void *) = NULL;

// ============================================================================
// Proxy: soinfo::call_constructors
// ============================================================================

static void proxy_call_constructors(void *soinfo) {
  struct dl_phdr_info dlinfo;
  bool do_callbacks = false;

  if (nh_soinfo_is_loading(soinfo) && g_init_cbs != NULL) {
    do_callbacks = true;
    nh_soinfo_to_dlinfo(soinfo, &dlinfo);

    // pre-callbacks
    pthread_rwlock_rdlock(&g_init_cbs_lock);
    for (nh_dl_cb_t *cb = g_init_cbs; cb; cb = cb->next) {
      if (cb->pre) cb->pre(&dlinfo, sizeof(dlinfo), cb->data);
    }
    pthread_rwlock_unlock(&g_init_cbs_lock);
  }

  g_orig_call_ctors(soinfo);

  if (do_callbacks) {
    // post-callbacks
    pthread_rwlock_rdlock(&g_init_cbs_lock);
    for (nh_dl_cb_t *cb = g_init_cbs; cb; cb = cb->next) {
      if (cb->post) cb->post(&dlinfo, sizeof(dlinfo), cb->data);
    }
    pthread_rwlock_unlock(&g_init_cbs_lock);
  }
}

// ============================================================================
// Proxy: soinfo::call_destructors
// ============================================================================

static void proxy_call_destructors(void *soinfo) {
  struct dl_phdr_info dlinfo;
  bool do_callbacks = false;

  if (!nh_soinfo_is_loading(soinfo) && g_fini_cbs != NULL) {
    do_callbacks = true;
    nh_soinfo_to_dlinfo(soinfo, &dlinfo);

    if (dlinfo.dlpi_addr != 0 && dlinfo.dlpi_name != NULL) {
      pthread_rwlock_rdlock(&g_fini_cbs_lock);
      for (nh_dl_cb_t *cb = g_fini_cbs; cb; cb = cb->next) {
        if (cb->pre) cb->pre(&dlinfo, sizeof(dlinfo), cb->data);
      }
      pthread_rwlock_unlock(&g_fini_cbs_lock);
    } else {
      do_callbacks = false;
    }
  }

  g_orig_call_dtors(soinfo);

  if (do_callbacks) {
    pthread_rwlock_rdlock(&g_fini_cbs_lock);
    for (nh_dl_cb_t *cb = g_fini_cbs; cb; cb = cb->next) {
      if (cb->post) cb->post(&dlinfo, sizeof(dlinfo), cb->data);
    }
    pthread_rwlock_unlock(&g_fini_cbs_lock);
  }
}

// ============================================================================
// Find linker64 base address and path from /proc/self/maps
// ============================================================================

static uintptr_t find_linker_base(char *path_out, size_t path_len) {
  FILE *fp = fopen("/proc/self/maps", "r");
  if (!fp) return 0;

  char line[512];
  uintptr_t base = 0;
  while (fgets(line, sizeof(line), fp)) {
    if (!strstr(line, "linker64")) continue;

    uintptr_t start;
    char perms[8];
    uintptr_t offset;
    if (sscanf(line, "%lx-%*lx %4s %lx", &start, perms, &offset) == 3) {
      if (offset == 0) {
        base = start;
        if (path_out) {
          char *p = strstr(line, "/");
          if (p) {
            char *nl = strchr(p, '\n');
            if (nl) *nl = '\0';
            strncpy(path_out, p, path_len - 1);
            path_out[path_len - 1] = '\0';
          }
        }
        break;
      }
    }
  }
  fclose(fp);
  return base;
}

// ============================================================================
// Find symbol offset in ELF .symtab (for LOCAL/HIDDEN symbols)
// ============================================================================

static uintptr_t find_sym_in_elf(const char *elf_path, const char *sym_name) {
  int fd = open(elf_path, O_RDONLY);
  if (fd < 0) return 0;

  struct stat st;
  if (fstat(fd, &st) != 0) { close(fd); return 0; }

  void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (map == MAP_FAILED) return 0;

  uintptr_t result = 0;
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;

  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) goto end;

  Elf64_Shdr *shdrs = (Elf64_Shdr *)((uint8_t *)map + ehdr->e_shoff);

  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (shdrs[i].sh_type != SHT_SYMTAB) continue;

    Elf64_Sym *syms = (Elf64_Sym *)((uint8_t *)map + shdrs[i].sh_offset);
    size_t sym_count = shdrs[i].sh_size / shdrs[i].sh_entsize;
    Elf64_Shdr *strtab_shdr = &shdrs[shdrs[i].sh_link];
    const char *strtab = (const char *)((uint8_t *)map + strtab_shdr->sh_offset);

    for (size_t j = 0; j < sym_count; j++) {
      if (syms[j].st_name == 0) continue;
      if (strcmp(strtab + syms[j].st_name, sym_name) == 0) {
        result = syms[j].st_value;
        goto end;
      }
    }
  }

end:
  munmap(map, st.st_size);
  return result;
}

// ============================================================================
// Get API level
// ============================================================================

static int get_api_level(void) {
  char buf[16] = {0};
  __system_property_get("ro.build.version.sdk", buf);
  return atoi(buf);
}

// ============================================================================
// Initialize linker monitoring
// ============================================================================

int nh_linker_init(void) {
  if (g_linker_inited) return 0;

  int api_level = get_api_level();
  const char *ctors_sym = (api_level >= 23) ? SYM_CALL_CTORS_M : SYM_CALL_CTORS_L;
  const char *dtors_sym = (api_level >= 23) ? SYM_CALL_DTORS_M : SYM_CALL_DTORS_L;

  // find linker64 base and path
  char linker_path[256] = {0};
  uintptr_t linker_base = find_linker_base(linker_path, sizeof(linker_path));
  if (linker_base == 0) {
    NH_LOG_E("linker: cannot find linker64 base");
    return -1;
  }
  NH_LOG_I("linker: base=0x%lx path=%s", (unsigned long)linker_base, linker_path);

  // find symbol offsets from ELF .symtab
  uintptr_t ctors_off = find_sym_in_elf(linker_path, ctors_sym);
  uintptr_t dtors_off = find_sym_in_elf(linker_path, dtors_sym);

  if (ctors_off == 0) {
    NH_LOG_E("linker: cannot find %s", ctors_sym);
    return -1;
  }
  if (dtors_off == 0) {
    NH_LOG_E("linker: cannot find %s", dtors_sym);
    return -1;
  }

  void *ctors_addr = (void *)(linker_base + ctors_off);
  void *dtors_addr = (void *)(linker_base + dtors_off);

  NH_LOG_I("linker: call_constructors=%p, call_destructors=%p", ctors_addr, dtors_addr);

  // hook call_constructors
  g_hook_ctors = newhook_hook_func_addr(ctors_addr, (void *)proxy_call_constructors,
                                        (void **)&g_orig_call_ctors);
  if (!g_hook_ctors) {
    NH_LOG_E("linker: hook call_constructors failed: %s", newhook_strerror(newhook_get_errno()));
    return -1;
  }

  // hook call_destructors
  g_hook_dtors = newhook_hook_func_addr(dtors_addr, (void *)proxy_call_destructors,
                                        (void **)&g_orig_call_dtors);
  if (!g_hook_dtors) {
    NH_LOG_E("linker: hook call_destructors failed: %s", newhook_strerror(newhook_get_errno()));
    newhook_unhook(g_hook_ctors);
    g_hook_ctors = NULL;
    return -1;
  }

  g_linker_inited = true;
  NH_LOG_I("linker: monitoring initialized");
  return 0;
}

// ============================================================================
// Callback registration
// ============================================================================

static int register_cb(nh_dl_cb_t **list, pthread_rwlock_t *lock,
                        nh_dl_info_cb_t pre, nh_dl_info_cb_t post, void *data) {
  nh_dl_cb_t *cb = calloc(1, sizeof(nh_dl_cb_t));
  if (!cb) return NH_ERR_OOM;

  cb->pre = pre;
  cb->post = post;
  cb->data = data;

  pthread_rwlock_wrlock(lock);
  cb->next = *list;
  *list = cb;
  pthread_rwlock_unlock(lock);

  return 0;
}

static int unregister_cb(nh_dl_cb_t **list, pthread_rwlock_t *lock,
                          nh_dl_info_cb_t pre, nh_dl_info_cb_t post, void *data) {
  pthread_rwlock_wrlock(lock);

  nh_dl_cb_t *prev = NULL;
  for (nh_dl_cb_t *cb = *list; cb; prev = cb, cb = cb->next) {
    if (cb->pre == pre && cb->post == post && cb->data == data) {
      if (prev) prev->next = cb->next;
      else *list = cb->next;
      pthread_rwlock_unlock(lock);
      free(cb);
      return 0;
    }
  }

  pthread_rwlock_unlock(lock);
  return NH_ERR_NOT_HOOKED;
}

int nh_linker_register_dl_init_cb(nh_dl_info_cb_t pre, nh_dl_info_cb_t post, void *data) {
  return register_cb(&g_init_cbs, &g_init_cbs_lock, pre, post, data);
}

int nh_linker_unregister_dl_init_cb(nh_dl_info_cb_t pre, nh_dl_info_cb_t post, void *data) {
  return unregister_cb(&g_init_cbs, &g_init_cbs_lock, pre, post, data);
}

int nh_linker_register_dl_fini_cb(nh_dl_info_cb_t pre, nh_dl_info_cb_t post, void *data) {
  return register_cb(&g_fini_cbs, &g_fini_cbs_lock, pre, post, data);
}

int nh_linker_unregister_dl_fini_cb(nh_dl_info_cb_t pre, nh_dl_info_cb_t post, void *data) {
  return unregister_cb(&g_fini_cbs, &g_fini_cbs_lock, pre, post, data);
}
