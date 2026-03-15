#ifndef NH_SAFE_H
#define NH_SAFE_H

#include <setjmp.h>
#include <signal.h>

// Initialize signal handlers for safe memory access.
int nh_safe_init(void);

// Thread-local jump buffer and flag for signal-based try/catch.
// Usage:
//   NH_SAFE_TRY() {
//     // potentially faulting code
//   }
//   NH_SAFE_CATCH() {
//     // code runs if SIGSEGV/SIGBUS occurred
//   }
//   NH_SAFE_END

extern _Thread_local sigjmp_buf nh_safe_jmp_buf;
extern _Thread_local volatile int nh_safe_flag;

#define NH_SAFE_TRY()                                \
  do {                                               \
    nh_safe_flag = 1;                                \
    if (sigsetjmp(nh_safe_jmp_buf, 1) == 0) {

#define NH_SAFE_CATCH()                              \
      nh_safe_flag = 0;                              \
    } else {                                         \
      nh_safe_flag = 0;

#define NH_SAFE_END                                  \
    }                                                \
  } while (0)

#endif // NH_SAFE_H
