#ifndef NH_A64_H
#define NH_A64_H

#include <stddef.h>
#include <stdint.h>

// ARM64 instruction types (PC-relative)
typedef enum {
  NH_A64_TYPE_IGNORED = 0,  // not PC-relative, copy as-is
  NH_A64_TYPE_B,            // B imm26
  NH_A64_TYPE_BL,           // BL imm26
  NH_A64_TYPE_B_COND,       // B.cond imm19
  NH_A64_TYPE_CBZ,          // CBZ Rt, imm19
  NH_A64_TYPE_CBNZ,         // CBNZ Rt, imm19
  NH_A64_TYPE_TBZ,          // TBZ Rt, #bit, imm14
  NH_A64_TYPE_TBNZ,         // TBNZ Rt, #bit, imm14
  NH_A64_TYPE_ADR,          // ADR Rd, imm21
  NH_A64_TYPE_ADRP,         // ADRP Rd, imm21 (page-aligned)
  NH_A64_TYPE_LDR_LIT_32,   // LDR Wt, label
  NH_A64_TYPE_LDR_LIT_64,   // LDR Xt, label
  NH_A64_TYPE_LDRSW_LIT,    // LDRSW Xt, label
  NH_A64_TYPE_LDR_SIMD_32,  // LDR St, label
  NH_A64_TYPE_LDR_SIMD_64,  // LDR Dt, label
  NH_A64_TYPE_LDR_SIMD_128, // LDR Qt, label
  NH_A64_TYPE_PRFM_LIT,     // PRFM label
} nh_a64_type_t;

// B instruction range: ±128MB
#define NH_A64_B_RANGE       (128 * 1024 * 1024)
// B.cond / CBZ / CBNZ / LDR literal range: ±1MB
#define NH_A64_BCOND_RANGE   (1 * 1024 * 1024)
// TBZ / TBNZ range: ±32KB
#define NH_A64_TBZ_RANGE     (32 * 1024)
// ADR range: ±1MB
#define NH_A64_ADR_RANGE     (1 * 1024 * 1024)
// ADRP range: ±4GB
#define NH_A64_ADRP_RANGE    (UINT64_C(4) * 1024 * 1024 * 1024)

// maximum rewritten length for a single instruction (bytes)
#define NH_A64_MAX_REWRITE_LEN  20

// absolute jump using LDR X17 + BR X17 + .quad addr (16 bytes)
#define NH_A64_ABS_JUMP_LEN     16

// Classify an ARM64 instruction.
nh_a64_type_t nh_a64_get_type(uint32_t inst);

// Get the worst-case rewritten length for an instruction of this type.
size_t nh_a64_get_rewrite_len(nh_a64_type_t type);

// Rewrite a single instruction, fixing PC-relative addressing.
// buf     : output buffer (must be large enough for worst-case)
// inst    : original instruction word
// old_pc  : original PC (address where inst was located)
// new_pc  : new PC (address in enter trampoline where rewritten code will live)
// Returns : number of bytes written to buf, or 0 on failure.
size_t nh_a64_rewrite(uint32_t *buf, uint32_t inst, uintptr_t old_pc, uintptr_t new_pc);

// Generate an absolute jump sequence: LDR X17, [PC, #8]; BR X17; .quad <addr>
// Returns 16 (NH_A64_ABS_JUMP_LEN).
size_t nh_a64_make_abs_jump(uint32_t *buf, uintptr_t addr);

// Generate a relative B instruction. Returns 4 on success, 0 if out of range.
size_t nh_a64_make_rel_jump(uint32_t *buf, uintptr_t from_pc, uintptr_t to_addr);

#endif // NH_A64_H
