#include "nh_safe.h"

#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

_Thread_local sigjmp_buf nh_safe_jmp_buf;
_Thread_local volatile int nh_safe_flag = 0;

static struct sigaction g_old_sa_segv;
static struct sigaction g_old_sa_bus;
static bool g_inited = false;

static void nh_safe_handler(int sig, siginfo_t *si, void *uc) {
  (void)si;
  (void)uc;

  if (nh_safe_flag) {
    nh_safe_flag = 0;
    siglongjmp(nh_safe_jmp_buf, 1);
  }

  // Not our fault — chain to previous handler
  struct sigaction *old_sa = (sig == SIGSEGV) ? &g_old_sa_segv : &g_old_sa_bus;
  if (old_sa->sa_flags & SA_SIGINFO) {
    if (old_sa->sa_sigaction != NULL) {
      old_sa->sa_sigaction(sig, si, uc);
      return;
    }
  } else {
    if (old_sa->sa_handler != SIG_DFL && old_sa->sa_handler != SIG_IGN) {
      old_sa->sa_handler(sig);
      return;
    }
  }

  // Re-raise with default handler
  signal(sig, SIG_DFL);
  raise(sig);
}

int nh_safe_init(void) {
  if (g_inited) return 0;

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = nh_safe_handler;
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
  sigfillset(&sa.sa_mask);

  if (sigaction(SIGSEGV, &sa, &g_old_sa_segv) != 0) return -1;
  if (sigaction(SIGBUS, &sa, &g_old_sa_bus) != 0) return -1;

  g_inited = true;
  return 0;
}
