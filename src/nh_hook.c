#include "nh_hook.h"

#include <string.h>
#include <sys/mman.h>

#include "nh_a64.h"
#include "nh_enter.h"
#include "nh_errno.h"
#include "nh_island.h"
#include "nh_log.h"
#include "nh_safe.h"
#include "nh_util.h"

// Strategy A backup length: 1 instruction = 4 bytes
#define BACKUP_LEN_ISLAND    4

// Strategy B backup length: LDR X17 + BR X17 + .quad addr = 16 bytes
#define BACKUP_LEN_NO_ISLAND 16

// ============================================================
// Build the enter trampoline: rewritten instructions + jump back
// ============================================================

static int build_enter(uintptr_t enter, uintptr_t target_addr,
                       const uint32_t *backup, size_t backup_len, size_t enter_size) {
  uint32_t *enter_buf = (uint32_t *)enter;
  size_t enter_offset = 0;
  size_t inst_count = backup_len / 4;

  // Rewrite each backed-up instruction
  for (size_t i = 0; i < inst_count; i++) {
    uint32_t inst = backup[i];
    uintptr_t old_pc = target_addr + i * 4;
    uintptr_t new_pc = enter + enter_offset;

    uint32_t rewrite_buf[8];  // max 20 bytes = 5 words
    size_t written = nh_a64_rewrite(rewrite_buf, inst, old_pc, new_pc);
    if (written == 0) {
      NH_LOG_E("hook: rewrite instruction %zu failed (inst=0x%08x)", i, inst);
      return NH_ERR_REWRITE;
    }

    // Check we don't overflow the enter trampoline
    if (enter_offset + written + NH_A64_ABS_JUMP_LEN > enter_size) {
      NH_LOG_E("hook: enter trampoline overflow (offset=%zu, written=%zu)", enter_offset, written);
      return NH_ERR_REWRITE;
    }

    memcpy(enter_buf + (enter_offset / 4), rewrite_buf, written);
    enter_offset += written;
  }

  // Append jump back to original code (after backed-up region)
  uintptr_t resume_addr = target_addr + backup_len;
  uintptr_t jump_pc = enter + enter_offset;

  // Try relative jump first
  size_t jump_len = nh_a64_make_rel_jump(
      enter_buf + (enter_offset / 4), jump_pc, resume_addr);
  if (jump_len == 0) {
    // Fall back to absolute jump
    jump_len = nh_a64_make_abs_jump(
        enter_buf + (enter_offset / 4), resume_addr);
  }
  enter_offset += jump_len;

  // Flush instruction cache for the entire enter trampoline
  nh_util_flush_cache(enter, enter_offset);

  NH_LOG_D("hook: enter built at %p, size=%zu, resume=%p",
           (void *)enter, enter_offset, (void *)resume_addr);
  return NH_OK;
}

// ============================================================
// Strategy A: hook with island
// Without landing pad: 4-byte backup (1 instruction)
// With landing pad:    8-byte backup (2 instructions)
// ============================================================

static int hook_with_island(nh_hook_t *hook, void **orig_func) {
  uintptr_t target = hook->target_addr;
  uintptr_t new_func = hook->new_func;

  // Detect BTI/PAC landing pad at target[0]
  uint32_t first_inst = *((uint32_t *)target);
  bool has_lp = nh_a64_is_landing_pad(first_inst);
  hook->has_landing_pad = has_lp;

  // B instruction PC and backup length depend on landing pad presence
  uintptr_t b_pc = has_lp ? target + 4 : target;
  size_t backup_len = has_lp ? (BACKUP_LEN_ISLAND + 4) : BACKUP_LEN_ISLAND;

  // 1. Allocate enter trampoline (64 bytes)
  uintptr_t enter = nh_enter_alloc(true);
  if (enter == 0) return NH_ERR_ALLOC_ENTER;

  // 2. Allocate island_exit near B instruction PC (within ±128MB)
  uintptr_t island_exit = nh_island_alloc(b_pc, NH_A64_B_RANGE - 4);
  if (island_exit == 0) {
    nh_enter_free(enter, true);
    return NH_ERR_ALLOC_ISLAND;
  }

  // 3. Backup instructions
  memcpy(hook->backup, (void *)target, backup_len);
  hook->backup_len = backup_len;

  // 4. Build enter trampoline (includes PACIASP if original had it)
  int r = build_enter(enter, target, hook->backup, backup_len,
                      NH_ENTER_WITH_ISLAND_SIZE);
  if (r != NH_OK) {
    nh_island_free(island_exit);
    nh_enter_free(enter, true);
    return r;
  }

  // 5. Write island_exit: absolute jump to new_func
  nh_a64_make_abs_jump((uint32_t *)island_exit, new_func);
  nh_util_flush_cache(island_exit, NH_A64_ABS_JUMP_LEN);

  // 6. Verify B range from b_pc to island_exit
  int64_t b_offset = (int64_t)island_exit - (int64_t)b_pc;
  if (b_offset < -(int64_t)NH_A64_B_RANGE || b_offset >= (int64_t)NH_A64_B_RANGE) {
    NH_LOG_E("hook: island_exit out of B range");
    nh_island_free(island_exit);
    nh_enter_free(enter, true);
    return NH_ERR_ALLOC_ISLAND;
  }

  // Make target page writable
  if (nh_util_mprotect(target, backup_len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    nh_island_free(island_exit);
    nh_enter_free(enter, true);
    return NH_ERR_MPROTECT;
  }

  // CRITICAL: Set orig_func BEFORE the patch takes effect.
  hook->enter = enter;
  hook->island_exit = island_exit;
  hook->with_island = true;
  if (orig_func != NULL) *orig_func = (void *)enter;

  // Build the patch buffer
  uint32_t patch[2];
  size_t patch_len;
  if (has_lp) {
    // [0] BTI c (replace PACIASP to avoid double-signing; keep BTI as-is)
    patch[0] = nh_a64_is_pac_sp(first_inst) ? NH_A64_INST_BTI_C : first_inst;
    // [1] B <island_exit>
    nh_a64_make_rel_jump(&patch[1], b_pc, island_exit);
    patch_len = 8;
  } else {
    nh_a64_make_rel_jump(&patch[0], target, island_exit);
    patch_len = 4;
  }

  // Atomic write with signal protection
  bool write_ok = true;
  NH_SAFE_TRY() {
    nh_util_write_inst(target, patch, patch_len);
  }
  NH_SAFE_CATCH() {
    write_ok = false;
  }
  NH_SAFE_END;

  nh_util_flush_cache(target, patch_len);
  nh_util_mprotect(target, backup_len, PROT_READ | PROT_EXEC);

  if (!write_ok) {
    hook->enter = 0;
    hook->island_exit = 0;
    hook->with_island = false;
    hook->has_landing_pad = false;
    if (orig_func != NULL) *orig_func = NULL;
    nh_island_free(island_exit);
    nh_enter_free(enter, true);
    return NH_ERR_PATCH;
  }

  hook->hooked = true;

  NH_LOG_I("hook: installed (island%s) target=%p, new=%p, enter=%p, island=%p",
           has_lp ? "+bti" : "", (void *)target, (void *)new_func,
           (void *)enter, (void *)island_exit);
  return NH_OK;
}

// ============================================================
// Strategy B: hook without island
// Without landing pad: 16-byte backup (4 instructions)
// With landing pad:    20-byte backup (5 instructions)
// ============================================================

static int hook_without_island(nh_hook_t *hook, size_t sym_size, void **orig_func) {
  uintptr_t target = hook->target_addr;
  uintptr_t new_func = hook->new_func;

  // Detect BTI/PAC landing pad (may already be set by Strategy A attempt)
  uint32_t first_inst = *((uint32_t *)target);
  bool has_lp = nh_a64_is_landing_pad(first_inst);
  hook->has_landing_pad = has_lp;

  size_t backup_len = has_lp ? (BACKUP_LEN_NO_ISLAND + 4) : BACKUP_LEN_NO_ISLAND;

  // Check that the function is large enough for the patch
  if (sym_size != 0 && sym_size < backup_len) {
    NH_LOG_E("hook: function too small (%zu < %zu)", sym_size, backup_len);
    return NH_ERR_FUNC_TOO_SMALL;
  }

  // 1. Allocate enter trampoline (256 bytes)
  uintptr_t enter = nh_enter_alloc(false);
  if (enter == 0) return NH_ERR_ALLOC_ENTER;

  // 2. Backup instructions
  memcpy(hook->backup, (void *)target, backup_len);
  hook->backup_len = backup_len;

  // 3. Build enter trampoline (includes PACIASP if original had it)
  int r = build_enter(enter, target, hook->backup, backup_len,
                      NH_ENTER_WITHOUT_ISLAND_SIZE);
  if (r != NH_OK) {
    nh_enter_free(enter, false);
    return r;
  }

  // 4. Build the patch
  // With LP:    BTI c + LDR X17 + BR X17 + .quad = 20 bytes
  // Without LP: LDR X17 + BR X17 + .quad           = 16 bytes
  uint32_t patch[5];
  size_t patch_offset = 0;
  if (has_lp) {
    patch[0] = nh_a64_is_pac_sp(first_inst) ? NH_A64_INST_BTI_C : first_inst;
    patch_offset = 1;
  }
  nh_a64_make_abs_jump(patch + patch_offset, new_func);
  size_t patch_len = backup_len;

  // 5. Patch target
  if (nh_util_mprotect(target, backup_len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    nh_enter_free(enter, false);
    return NH_ERR_MPROTECT;
  }

  // CRITICAL: Set orig_func BEFORE the patch takes effect.
  hook->enter = enter;
  hook->island_exit = 0;
  hook->with_island = false;
  if (orig_func != NULL) *orig_func = (void *)enter;

  bool write_ok = true;
  NH_SAFE_TRY() {
    nh_util_write_inst(target, patch, patch_len);
  }
  NH_SAFE_CATCH() {
    write_ok = false;
  }
  NH_SAFE_END;

  nh_util_flush_cache(target, backup_len);
  nh_util_mprotect(target, backup_len, PROT_READ | PROT_EXEC);

  if (!write_ok) {
    hook->enter = 0;
    hook->has_landing_pad = false;
    if (orig_func != NULL) *orig_func = NULL;
    nh_enter_free(enter, false);
    return NH_ERR_PATCH;
  }

  hook->hooked = true;

  NH_LOG_I("hook: installed (no-island%s) target=%p, new=%p, enter=%p",
           has_lp ? "+bti" : "", (void *)target, (void *)new_func, (void *)enter);
  return NH_OK;
}

// ============================================================
// Public API
// ============================================================

int nh_hook_install(nh_hook_t *hook, uintptr_t target_addr, uintptr_t new_func,
                    void **orig_func, size_t sym_size) {
  memset(hook, 0, sizeof(*hook));
  hook->target_addr = target_addr;
  hook->new_func = new_func;

  // Strategy A: try with island first (preferred, only 4-byte patch)
  // orig_func is set inside the strategy BEFORE the patch takes effect.
  int r = hook_with_island(hook, orig_func);
  if (r == NH_OK) return NH_OK;

  NH_LOG_D("hook: island strategy failed (%d), trying no-island", r);

  // Strategy B: without island (16-byte patch)
  r = hook_without_island(hook, sym_size, orig_func);
  if (r == NH_OK) return NH_OK;

  return r;
}

int nh_hook_uninstall(nh_hook_t *hook) {
  if (!hook->hooked) return NH_ERR_NOT_HOOKED;

  uintptr_t target = hook->target_addr;
  size_t backup_len = hook->backup_len;

  // Restore original instructions
  if (nh_util_mprotect(target, backup_len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    return NH_ERR_MPROTECT;
  }

  bool write_ok = true;
  NH_SAFE_TRY() {
    nh_util_write_inst(target, hook->backup, backup_len);
  }
  NH_SAFE_CATCH() {
    write_ok = false;
  }
  NH_SAFE_END;

  nh_util_flush_cache(target, backup_len);
  nh_util_mprotect(target, backup_len, PROT_READ | PROT_EXEC);

  if (!write_ok) return NH_ERR_PATCH;

  // Free resources (delayed reuse)
  if (hook->island_exit != 0) {
    nh_island_free(hook->island_exit);
  }
  nh_enter_free(hook->enter, hook->with_island);

  hook->hooked = false;

  NH_LOG_I("hook: uninstalled target=%p", (void *)target);
  return NH_OK;
}

int nh_hook_update_new_func(nh_hook_t *hook, uintptr_t new_func) {
  if (!hook->hooked) return NH_ERR_NOT_HOOKED;

  // The .quad address is at offset +8 from the LDR X17,[PC,#8] instruction.
  // Strategy A (island): island_exit+0 = LDR; +4 = BR; +8 = .quad
  // Strategy B (no-island): the LDR starts at target+0 or target+4 (if landing pad)
  uintptr_t addr_loc;
  if (hook->with_island) {
    addr_loc = hook->island_exit + 8;
  } else {
    // LDR X17 is at target+0 normally, or target+4 if BTI c occupies target+0
    uintptr_t ldr_pc = hook->target_addr + (hook->has_landing_pad ? 4 : 0);
    addr_loc = ldr_pc + 8;
  }

  // Atomic 8-byte write to update the target address
  __atomic_store_n((uint64_t *)addr_loc, (uint64_t)new_func, __ATOMIC_SEQ_CST);
  nh_util_flush_cache(addr_loc, 8);

  hook->new_func = new_func;

  NH_LOG_D("hook: updated target=%p -> new_func=%p",
           (void *)hook->target_addr, (void *)new_func);
  return NH_OK;
}
