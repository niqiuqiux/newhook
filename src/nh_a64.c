#include "nh_a64.h"

#include <stdbool.h>
#include <string.h>

#include "nh_util.h"

// ============================================================
// ARM64 instruction encoding helpers
// ============================================================

// B / BL: [31] op | [30:26] 00101 | [25:0] imm26
static bool is_b_or_bl(uint32_t inst) {
  return (inst & 0x7C000000) == 0x14000000;
}

// B.cond: [31:25] 0101010 | [24] 0 | [23:5] imm19 | [4] 0 | [3:0] cond
static bool is_b_cond(uint32_t inst) {
  return (inst & 0xFF000010) == 0x54000000;
}

// CBZ/CBNZ: [31] sf | [30:25] 011010 | [24] op | [23:5] imm19 | [4:0] Rt
static bool is_cbz_cbnz(uint32_t inst) {
  return (inst & 0x7E000000) == 0x34000000;
}

// TBZ/TBNZ: [31] b5 | [30:25] 011011 | [24] op | [23:19] b40 | [18:5] imm14 | [4:0] Rt
static bool is_tbz_tbnz(uint32_t inst) {
  return (inst & 0x7E000000) == 0x36000000;
}

// ADR/ADRP: [31] op | [30:29] immlo | [28:24] 10000 | [23:5] immhi | [4:0] Rd
static bool is_adr(uint32_t inst) {
  return (inst & 0x9F000000) == 0x10000000;  // op=0
}
static bool is_adrp(uint32_t inst) {
  return (inst & 0x9F000000) == 0x90000000;  // op=1
}

// LDR literal: [31:30] opc | [29:24] 011000 | [23:5] imm19 | [4:0] Rt
// opc: 00=LDR(32), 01=LDR(64), 10=LDRSW, 11=PRFM
static bool is_ldr_lit(uint32_t inst) {
  return (inst & 0x3B000000) == 0x18000000;
}

// LDR SIMD literal: [31:30] opc | [29:24] 011100 | [23:5] imm19 | [4:0] Rt
static bool is_ldr_simd_lit(uint32_t inst) {
  return (inst & 0x3B000000) == 0x1C000000;
}

// ============================================================
// Public: classify instruction
// ============================================================

nh_a64_type_t nh_a64_get_type(uint32_t inst) {
  if (is_b_or_bl(inst)) {
    return (inst & 0x80000000) ? NH_A64_TYPE_BL : NH_A64_TYPE_B;
  }
  if (is_b_cond(inst)) return NH_A64_TYPE_B_COND;
  if (is_cbz_cbnz(inst)) {
    return (inst & 0x01000000) ? NH_A64_TYPE_CBNZ : NH_A64_TYPE_CBZ;
  }
  if (is_tbz_tbnz(inst)) {
    return (inst & 0x01000000) ? NH_A64_TYPE_TBNZ : NH_A64_TYPE_TBZ;
  }
  if (is_adr(inst)) return NH_A64_TYPE_ADR;
  if (is_adrp(inst)) return NH_A64_TYPE_ADRP;
  if (is_ldr_lit(inst)) {
    uint32_t opc = NH_BITS_GET_32(inst, 31, 30);
    switch (opc) {
      case 0: return NH_A64_TYPE_LDR_LIT_32;
      case 1: return NH_A64_TYPE_LDR_LIT_64;
      case 2: return NH_A64_TYPE_LDRSW_LIT;
      case 3: return NH_A64_TYPE_PRFM_LIT;
    }
  }
  if (is_ldr_simd_lit(inst)) {
    uint32_t opc = NH_BITS_GET_32(inst, 31, 30);
    switch (opc) {
      case 0: return NH_A64_TYPE_LDR_SIMD_32;
      case 1: return NH_A64_TYPE_LDR_SIMD_64;
      case 2: return NH_A64_TYPE_LDR_SIMD_128;
    }
  }
  return NH_A64_TYPE_IGNORED;
}

// ============================================================
// Worst-case rewritten length per type
// ============================================================

size_t nh_a64_get_rewrite_len(nh_a64_type_t type) {
  switch (type) {
    case NH_A64_TYPE_IGNORED:     return 4;
    case NH_A64_TYPE_B:           return 20;  // inline abs jump
    case NH_A64_TYPE_BL:          return 20;
    case NH_A64_TYPE_B_COND:      return 20;  // inv_cond + abs jump
    case NH_A64_TYPE_CBZ:         return 20;
    case NH_A64_TYPE_CBNZ:        return 20;
    case NH_A64_TYPE_TBZ:         return 20;
    case NH_A64_TYPE_TBNZ:        return 20;
    case NH_A64_TYPE_ADR:         return 16;  // LDR Rd + B + .quad
    case NH_A64_TYPE_ADRP:        return 16;
    case NH_A64_TYPE_LDR_LIT_32:  return 20;  // LDR Xt + B + .quad + LDR Wt,[Xt]
    case NH_A64_TYPE_LDR_LIT_64:  return 20;
    case NH_A64_TYPE_LDRSW_LIT:   return 20;
    case NH_A64_TYPE_LDR_SIMD_32: return 20;  // LDR X17 + B + .quad + LDR St,[X17]
    case NH_A64_TYPE_LDR_SIMD_64: return 20;
    case NH_A64_TYPE_LDR_SIMD_128:return 20;
    case NH_A64_TYPE_PRFM_LIT:    return 4;   // NOP (prefetch is a hint)
    default:                      return 4;
  }
}

// ============================================================
// Instruction encoding builders
// ============================================================

static uint32_t make_b(int64_t offset) {
  // B: 000101 imm26, offset in bytes
  uint32_t imm26 = (uint32_t)((offset >> 2) & 0x03FFFFFF);
  return 0x14000000 | imm26;
}

static uint32_t make_bl(int64_t offset) {
  uint32_t imm26 = (uint32_t)((offset >> 2) & 0x03FFFFFF);
  return 0x94000000 | imm26;
}

static uint32_t make_b_cond(int64_t offset, uint32_t cond) {
  uint32_t imm19 = (uint32_t)((offset >> 2) & 0x7FFFF);
  return 0x54000000 | (imm19 << 5) | cond;
}

static uint32_t make_cbz(uint32_t sf, int64_t offset, uint32_t rt) {
  uint32_t imm19 = (uint32_t)((offset >> 2) & 0x7FFFF);
  return (sf << 31) | 0x34000000 | (imm19 << 5) | rt;
}

static uint32_t make_cbnz(uint32_t sf, int64_t offset, uint32_t rt) {
  uint32_t imm19 = (uint32_t)((offset >> 2) & 0x7FFFF);
  return (sf << 31) | 0x35000000 | (imm19 << 5) | rt;
}

static uint32_t make_tbz(uint32_t b5, uint32_t b40, int64_t offset, uint32_t rt) {
  uint32_t imm14 = (uint32_t)((offset >> 2) & 0x3FFF);
  return (b5 << 31) | 0x36000000 | (b40 << 19) | (imm14 << 5) | rt;
}

static uint32_t make_tbnz(uint32_t b5, uint32_t b40, int64_t offset, uint32_t rt) {
  uint32_t imm14 = (uint32_t)((offset >> 2) & 0x3FFF);
  return (b5 << 31) | 0x37000000 | (b40 << 19) | (imm14 << 5) | rt;
}

static uint32_t make_ldr_lit_x(uint32_t rt, int64_t offset) {
  // LDR Xt, label: 01 011 0 00 imm19 Rt
  uint32_t imm19 = (uint32_t)((offset >> 2) & 0x7FFFF);
  return 0x58000000 | (imm19 << 5) | rt;
}

static uint32_t make_nop(void) {
  return 0xD503201F;
}

// ============================================================
// Inline absolute load pattern:
//   LDR Rd, [PC, #8]     load the 8-byte value at PC+8 into Rd
//   B .+12               skip over the 8-byte data
//   .quad <value>         8-byte absolute value
// Total: 16 bytes
// ============================================================
static size_t emit_abs_load_reg(uint32_t *buf, uint32_t rd, uint64_t value) {
  buf[0] = make_ldr_lit_x(rd, 8);         // LDR Xd, [PC, #8]
  buf[1] = make_b(12);                     // B .+12  (skip 8 bytes of data)
  *((uint64_t *)&buf[2]) = value;          // .quad value
  return 16;
}

// ============================================================
// Inline absolute jump pattern for conditional out-of-range:
//   <inverted_cond_branch skip>    4 bytes
//   LDR X17, [PC, #8]             4 bytes
//   BR  X17                       4 bytes
//   .quad <target>                 8 bytes
//   skip:
// Total: 20 bytes
// ============================================================
static size_t emit_cond_abs_jump(uint32_t *buf, uint32_t inv_cond_inst, uint64_t target) {
  buf[0] = inv_cond_inst;                  // inverted condition → skip
  buf[1] = make_ldr_lit_x(17, 8);         // LDR X17, [PC, #8]
  buf[2] = 0xD61F0220;                     // BR X17
  *((uint64_t *)&buf[3]) = target;         // .quad target
  return 20;
}

// ============================================================
// Public: absolute jump
// ============================================================

size_t nh_a64_make_abs_jump(uint32_t *buf, uintptr_t addr) {
  buf[0] = make_ldr_lit_x(17, 8);         // LDR X17, [PC, #8]
  buf[1] = 0xD61F0220;                     // BR X17
  *((uint64_t *)&buf[2]) = (uint64_t)addr; // .quad addr
  return 16;
}

size_t nh_a64_make_rel_jump(uint32_t *buf, uintptr_t from_pc, uintptr_t to_addr) {
  int64_t offset = (int64_t)to_addr - (int64_t)from_pc;
  if (offset < -(int64_t)NH_A64_B_RANGE || offset >= (int64_t)NH_A64_B_RANGE) {
    return 0;  // out of range
  }
  buf[0] = make_b(offset);
  return 4;
}

// ============================================================
// Public: rewrite a single instruction
// ============================================================

size_t nh_a64_rewrite(uint32_t *buf, uint32_t inst, uintptr_t old_pc, uintptr_t new_pc) {
  nh_a64_type_t type = nh_a64_get_type(inst);
  int64_t diff;
  int64_t target;

  switch (type) {

  case NH_A64_TYPE_IGNORED:
    buf[0] = inst;
    return 4;

  // ── B / BL (imm26, ±128MB) ──
  case NH_A64_TYPE_B: {
    int64_t imm26 = NH_SIGN_EXTEND_64(NH_BITS_GET_32(inst, 25, 0), 26);
    target = (int64_t)old_pc + (imm26 << 2);
    diff = target - (int64_t)new_pc;
    if (diff >= -(int64_t)NH_A64_B_RANGE && diff < (int64_t)NH_A64_B_RANGE) {
      buf[0] = make_b(diff);
      return 4;
    }
    // Out of range: inline absolute jump
    buf[0] = make_ldr_lit_x(17, 8);
    buf[1] = 0xD61F0220;  // BR X17
    *((uint64_t *)&buf[2]) = (uint64_t)target;
    return 16;
  }

  case NH_A64_TYPE_BL: {
    int64_t imm26 = NH_SIGN_EXTEND_64(NH_BITS_GET_32(inst, 25, 0), 26);
    target = (int64_t)old_pc + (imm26 << 2);
    diff = target - (int64_t)new_pc;
    if (diff >= -(int64_t)NH_A64_B_RANGE && diff < (int64_t)NH_A64_B_RANGE) {
      buf[0] = make_bl(diff);
      return 4;
    }
    // Out of range: LDR X17, #8; BLR X17; .quad target
    buf[0] = make_ldr_lit_x(17, 8);
    buf[1] = 0xD63F0220;  // BLR X17
    *((uint64_t *)&buf[2]) = (uint64_t)target;
    return 16;
  }

  // ── B.cond (imm19, ±1MB) ──
  case NH_A64_TYPE_B_COND: {
    uint32_t cond = NH_BITS_GET_32(inst, 3, 0);
    int64_t imm19 = NH_SIGN_EXTEND_64(NH_BITS_GET_32(inst, 23, 5), 19);
    target = (int64_t)old_pc + (imm19 << 2);
    diff = target - (int64_t)new_pc;
    if (diff >= -(int64_t)NH_A64_BCOND_RANGE && diff < (int64_t)NH_A64_BCOND_RANGE) {
      buf[0] = make_b_cond(diff, cond);
      return 4;
    }
    // Invert condition: B.inv_cond <skip>; LDR X17; BR X17; .quad target
    uint32_t inv_cond = cond ^ 1;
    uint32_t inv_inst = make_b_cond(20, inv_cond);  // skip 20 bytes = 5 words
    return emit_cond_abs_jump(buf, inv_inst, (uint64_t)target);
  }

  // ── CBZ (imm19, ±1MB) ──
  case NH_A64_TYPE_CBZ: {
    uint32_t sf = NH_BITS_GET_32(inst, 31, 31);
    uint32_t rt = NH_BITS_GET_32(inst, 4, 0);
    int64_t imm19 = NH_SIGN_EXTEND_64(NH_BITS_GET_32(inst, 23, 5), 19);
    target = (int64_t)old_pc + (imm19 << 2);
    diff = target - (int64_t)new_pc;
    if (diff >= -(int64_t)NH_A64_BCOND_RANGE && diff < (int64_t)NH_A64_BCOND_RANGE) {
      buf[0] = make_cbz(sf, diff, rt);
      return 4;
    }
    // Invert: CBNZ Rt, <skip>; abs jump to target
    uint32_t inv_inst = make_cbnz(sf, 20, rt);
    return emit_cond_abs_jump(buf, inv_inst, (uint64_t)target);
  }

  // ── CBNZ (imm19, ±1MB) ──
  case NH_A64_TYPE_CBNZ: {
    uint32_t sf = NH_BITS_GET_32(inst, 31, 31);
    uint32_t rt = NH_BITS_GET_32(inst, 4, 0);
    int64_t imm19 = NH_SIGN_EXTEND_64(NH_BITS_GET_32(inst, 23, 5), 19);
    target = (int64_t)old_pc + (imm19 << 2);
    diff = target - (int64_t)new_pc;
    if (diff >= -(int64_t)NH_A64_BCOND_RANGE && diff < (int64_t)NH_A64_BCOND_RANGE) {
      buf[0] = make_cbnz(sf, diff, rt);
      return 4;
    }
    uint32_t inv_inst = make_cbz(sf, 20, rt);
    return emit_cond_abs_jump(buf, inv_inst, (uint64_t)target);
  }

  // ── TBZ (imm14, ±32KB) ──
  case NH_A64_TYPE_TBZ: {
    uint32_t b5 = NH_BITS_GET_32(inst, 31, 31);
    uint32_t b40 = NH_BITS_GET_32(inst, 23, 19);
    uint32_t rt = NH_BITS_GET_32(inst, 4, 0);
    int64_t imm14 = NH_SIGN_EXTEND_64(NH_BITS_GET_32(inst, 18, 5), 14);
    target = (int64_t)old_pc + (imm14 << 2);
    diff = target - (int64_t)new_pc;
    if (diff >= -(int64_t)NH_A64_TBZ_RANGE && diff < (int64_t)NH_A64_TBZ_RANGE) {
      buf[0] = make_tbz(b5, b40, diff, rt);
      return 4;
    }
    // Invert: TBNZ <skip>; abs jump
    uint32_t inv_inst = make_tbnz(b5, b40, 20, rt);
    return emit_cond_abs_jump(buf, inv_inst, (uint64_t)target);
  }

  // ── TBNZ (imm14, ±32KB) ──
  case NH_A64_TYPE_TBNZ: {
    uint32_t b5 = NH_BITS_GET_32(inst, 31, 31);
    uint32_t b40 = NH_BITS_GET_32(inst, 23, 19);
    uint32_t rt = NH_BITS_GET_32(inst, 4, 0);
    int64_t imm14 = NH_SIGN_EXTEND_64(NH_BITS_GET_32(inst, 18, 5), 14);
    target = (int64_t)old_pc + (imm14 << 2);
    diff = target - (int64_t)new_pc;
    if (diff >= -(int64_t)NH_A64_TBZ_RANGE && diff < (int64_t)NH_A64_TBZ_RANGE) {
      buf[0] = make_tbnz(b5, b40, diff, rt);
      return 4;
    }
    uint32_t inv_inst = make_tbz(b5, b40, 20, rt);
    return emit_cond_abs_jump(buf, inv_inst, (uint64_t)target);
  }

  // ── ADR (±1MB) ──
  case NH_A64_TYPE_ADR: {
    uint32_t rd = NH_BITS_GET_32(inst, 4, 0);
    uint32_t immlo = NH_BITS_GET_32(inst, 30, 29);
    uint32_t immhi = NH_BITS_GET_32(inst, 23, 5);
    int64_t imm = NH_SIGN_EXTEND_64((immhi << 2) | immlo, 21);
    uint64_t value = (uint64_t)((int64_t)old_pc + imm);
    // Try to re-encode for new_pc
    int64_t new_imm = (int64_t)value - (int64_t)new_pc;
    if (new_imm >= -(int64_t)NH_A64_ADR_RANGE && new_imm < (int64_t)NH_A64_ADR_RANGE) {
      uint32_t uimm = (uint32_t)new_imm & 0x1FFFFF;
      uint32_t new_immlo = uimm & 0x3;
      uint32_t new_immhi = (uimm >> 2) & 0x7FFFF;
      buf[0] = (inst & 0x9F00001F) | (new_immlo << 29) | (new_immhi << 5);
      return 4;
    }
    // Out of range: absolute load
    return emit_abs_load_reg(buf, rd, value);
  }

  // ── ADRP (±4GB, page-aligned) ──
  case NH_A64_TYPE_ADRP: {
    uint32_t rd = NH_BITS_GET_32(inst, 4, 0);
    uint32_t immlo = NH_BITS_GET_32(inst, 30, 29);
    uint32_t immhi = NH_BITS_GET_32(inst, 23, 5);
    int64_t imm = NH_SIGN_EXTEND_64((immhi << 2) | immlo, 21);
    uint64_t value = (uint64_t)(((int64_t)old_pc & ~0xFFFLL) + (imm << 12));
    // Try to re-encode for new_pc
    int64_t new_imm = (int64_t)(value - ((uint64_t)new_pc & ~0xFFFULL));
    int64_t new_imm_pages = new_imm >> 12;
    if (new_imm_pages >= -(int64_t)(NH_A64_ADRP_RANGE >> 12) &&
        new_imm_pages < (int64_t)(NH_A64_ADRP_RANGE >> 12)) {
      uint32_t uimm = (uint32_t)new_imm_pages & 0x1FFFFF;
      uint32_t new_immlo = uimm & 0x3;
      uint32_t new_immhi = (uimm >> 2) & 0x7FFFF;
      buf[0] = (inst & 0x9F00001F) | (new_immlo << 29) | (new_immhi << 5);
      return 4;
    }
    return emit_abs_load_reg(buf, rd, value);
  }

  // ── LDR literal 32-bit ──
  case NH_A64_TYPE_LDR_LIT_32: {
    uint32_t rt = NH_BITS_GET_32(inst, 4, 0);
    int64_t imm19 = NH_SIGN_EXTEND_64(NH_BITS_GET_32(inst, 23, 5), 19);
    uint64_t mem_addr = (uint64_t)((int64_t)old_pc + (imm19 << 2));
    // Try to re-encode
    diff = (int64_t)mem_addr - (int64_t)new_pc;
    if (diff >= -(int64_t)NH_A64_BCOND_RANGE && diff < (int64_t)NH_A64_BCOND_RANGE) {
      uint32_t new_imm19 = (uint32_t)((diff >> 2) & 0x7FFFF);
      buf[0] = (inst & 0xFF00001F) | (new_imm19 << 5);
      return 4;
    }
    // Out of range: LDR Xt, [PC,#8]; B .+12; .quad mem_addr; LDR Wt, [Xt]
    emit_abs_load_reg(buf, rt, mem_addr);    // 16 bytes (loads addr into Xt)
    // LDR Wt, [Xt, #0]
    buf[4] = 0xB9400000 | (rt << 5) | rt;   // LDR Wt, [Xt]
    return 20;
  }

  // ── LDR literal 64-bit ──
  case NH_A64_TYPE_LDR_LIT_64: {
    uint32_t rt = NH_BITS_GET_32(inst, 4, 0);
    int64_t imm19 = NH_SIGN_EXTEND_64(NH_BITS_GET_32(inst, 23, 5), 19);
    uint64_t mem_addr = (uint64_t)((int64_t)old_pc + (imm19 << 2));
    diff = (int64_t)mem_addr - (int64_t)new_pc;
    if (diff >= -(int64_t)NH_A64_BCOND_RANGE && diff < (int64_t)NH_A64_BCOND_RANGE) {
      uint32_t new_imm19 = (uint32_t)((diff >> 2) & 0x7FFFF);
      buf[0] = (inst & 0xFF00001F) | (new_imm19 << 5);
      return 4;
    }
    emit_abs_load_reg(buf, rt, mem_addr);
    // LDR Xt, [Xt, #0]
    buf[4] = 0xF9400000 | (rt << 5) | rt;
    return 20;
  }

  // ── LDRSW literal ──
  case NH_A64_TYPE_LDRSW_LIT: {
    uint32_t rt = NH_BITS_GET_32(inst, 4, 0);
    int64_t imm19 = NH_SIGN_EXTEND_64(NH_BITS_GET_32(inst, 23, 5), 19);
    uint64_t mem_addr = (uint64_t)((int64_t)old_pc + (imm19 << 2));
    diff = (int64_t)mem_addr - (int64_t)new_pc;
    if (diff >= -(int64_t)NH_A64_BCOND_RANGE && diff < (int64_t)NH_A64_BCOND_RANGE) {
      uint32_t new_imm19 = (uint32_t)((diff >> 2) & 0x7FFFF);
      buf[0] = (inst & 0xFF00001F) | (new_imm19 << 5);
      return 4;
    }
    emit_abs_load_reg(buf, rt, mem_addr);
    // LDRSW Xt, [Xt, #0]
    buf[4] = 0xB9800000 | (rt << 5) | rt;
    return 20;
  }

  // ── LDR SIMD literal (32/64/128-bit) ──
  // Uses X17 as scratch register
  case NH_A64_TYPE_LDR_SIMD_32:
  case NH_A64_TYPE_LDR_SIMD_64:
  case NH_A64_TYPE_LDR_SIMD_128: {
    uint32_t rt = NH_BITS_GET_32(inst, 4, 0);
    int64_t imm19 = NH_SIGN_EXTEND_64(NH_BITS_GET_32(inst, 23, 5), 19);
    uint64_t mem_addr = (uint64_t)((int64_t)old_pc + (imm19 << 2));
    diff = (int64_t)mem_addr - (int64_t)new_pc;
    if (diff >= -(int64_t)NH_A64_BCOND_RANGE && diff < (int64_t)NH_A64_BCOND_RANGE) {
      uint32_t new_imm19 = (uint32_t)((diff >> 2) & 0x7FFFF);
      buf[0] = (inst & 0xFF00001F) | (new_imm19 << 5);
      return 4;
    }
    // LDR X17, [PC,#8]; B .+12; .quad mem_addr; LDR St/Dt/Qt, [X17]
    emit_abs_load_reg(buf, 17, mem_addr);
    // Generate the SIMD load from [X17]
    if (type == NH_A64_TYPE_LDR_SIMD_32) {
      buf[4] = 0xBD400000 | (17 << 5) | rt;   // LDR St, [X17]
    } else if (type == NH_A64_TYPE_LDR_SIMD_64) {
      buf[4] = 0xFD400000 | (17 << 5) | rt;   // LDR Dt, [X17]
    } else {
      buf[4] = 0x3DC00000 | (17 << 5) | rt;   // LDR Qt, [X17]
    }
    return 20;
  }

  // ── PRFM literal ──
  case NH_A64_TYPE_PRFM_LIT: {
    int64_t imm19 = NH_SIGN_EXTEND_64(NH_BITS_GET_32(inst, 23, 5), 19);
    uint64_t mem_addr = (uint64_t)((int64_t)old_pc + (imm19 << 2));
    diff = (int64_t)mem_addr - (int64_t)new_pc;
    if (diff >= -(int64_t)NH_A64_BCOND_RANGE && diff < (int64_t)NH_A64_BCOND_RANGE) {
      uint32_t new_imm19 = (uint32_t)((diff >> 2) & 0x7FFFF);
      buf[0] = (inst & 0xFF00001F) | (new_imm19 << 5);
      return 4;
    }
    // Prefetch is a hint — just NOP if out of range
    buf[0] = make_nop();
    return 4;
  }

  default:
    buf[0] = inst;
    return 4;
  }
}
