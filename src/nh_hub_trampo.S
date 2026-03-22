// nh_hub_trampo.S — ARM64 hub trampoline template for SHARED mode
// Reference: shadowhook/src/main/cpp/sh_hub.c trampoline template
//
// This is a position-independent code template that gets copied to
// executable memory. The data section at the end is patched with
// actual function/hub pointers before use.

#include <asm/unistd.h>

.text
.align 4

// ============================================================================
// Hub trampoline template
// ============================================================================

.global nh_hub_trampo_template
.type nh_hub_trampo_template, %function
nh_hub_trampo_template:

    // BTI landing pad — allows indirect branches (BR/BLR) to this address.
    // Currently MAP_ANONYMOUS pages don't enforce BTI, but this is defensive
    // in case future kernels change that policy.
    hint    #34                     // BTI c

    // Save parameter registers (x0-x7), XR(x8), LR, and SIMD registers (q0-q7)
    stp   x0, x1, [sp, #-0xd0]!    // pre-decrement sp by 0xd0, save x0-x1
    stp   x2, x3, [sp, #0x10]
    stp   x4, x5, [sp, #0x20]
    stp   x6, x7, [sp, #0x30]
    stp   x8, lr, [sp, #0x40]
    stp   q0, q1, [sp, #0x50]
    stp   q2, q3, [sp, #0x70]
    stp   q4, q5, [sp, #0x90]
    stp   q6, q7, [sp, #0xb0]

    // Call nh_hub_push_stack_impl(hub_ptr, return_address)
    ldr   x0, .L_hub_ptr            // x0 = hub pointer
    mov   x1, lr                    // x1 = return address (LR)
    ldr   x16, .L_push_stack        // x16 = push_stack function pointer
    blr   x16                       // call -> returns proxy func addr in x0

    // Save result to x16
    mov   x16, x0

    // Restore all registers
    ldp   q6, q7, [sp, #0xb0]
    ldp   q4, q5, [sp, #0x90]
    ldp   q2, q3, [sp, #0x70]
    ldp   q0, q1, [sp, #0x50]
    ldp   x8, lr, [sp, #0x40]
    ldp   x6, x7, [sp, #0x30]
    ldp   x4, x5, [sp, #0x20]
    ldp   x2, x3, [sp, #0x10]
    ldp   x0, x1, [sp], #0xd0      // restore x0-x1, post-increment sp

    // Jump to proxy function (tail call)
    br    x16

// ============================================================================
// Data section (patched at runtime)
// ============================================================================

.global nh_hub_trampo_template_data
nh_hub_trampo_template_data:
.L_push_stack:
    .quad 0                         // patched: pointer to nh_hub_push_stack_impl
.L_hub_ptr:
    .quad 0                         // patched: pointer to nh_hub_t
