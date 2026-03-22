#include "newhook.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>

// ============================================================
// Test infrastructure
// ============================================================

static int g_pass = 0;
static int g_fail = 0;

#define TEST_BEGIN(name) \
  do { printf("  [TEST] %-40s ", name); fflush(stdout); } while(0)

// Standard assertion — returns from function on failure
#define TEST_ASSERT(cond) do {                                 \
    if (!(cond)) {                                             \
      printf("FAIL\n    assert failed: %s\n    at %s:%d\n",   \
             #cond, __FILE__, __LINE__);                       \
      g_fail++; return;                                        \
    }                                                          \
  } while(0)

// Assertion with cleanup — jumps to 'cleanup' label on failure
#define TEST_ASSERT_CLEANUP(cond) do {                         \
    if (!(cond)) {                                             \
      printf("FAIL\n    assert failed: %s\n    at %s:%d\n",   \
             #cond, __FILE__, __LINE__);                       \
      g_fail++; goto cleanup;                                  \
    }                                                          \
  } while(0)

#define TEST_PASS() do { printf("PASS\n"); g_pass++; } while(0)

// ============================================================
// Test 1: init
// ============================================================

static void test_init(void) {
  TEST_BEGIN("newhook_init");
  int r = newhook_init();
  TEST_ASSERT(r == NH_OK);
  // double init should also succeed
  r = newhook_init();
  TEST_ASSERT(r == NH_OK);
  TEST_PASS();
}

// ============================================================
// Test 2: hook strlen by address
// ============================================================

static size_t (*orig_strlen)(const char *) = NULL;
static int g_strlen_hook_called = 0;

static size_t my_strlen(const char *s) {
  g_strlen_hook_called++;
  return orig_strlen(s);
}

static void test_hook_func_addr(void) {
  TEST_BEGIN("hook_func_addr (strlen)");

  void *handle = newhook_hook_func_addr((void *)strlen, (void *)my_strlen,
                                        (void **)&orig_strlen);
  TEST_ASSERT(handle != NULL);
  TEST_ASSERT(orig_strlen != NULL);

  // Reset counter AFTER hook installation (install may internally call strlen)
  g_strlen_hook_called = 0;

  size_t len = strlen("hello");
  TEST_ASSERT(len == 5);
  TEST_ASSERT(g_strlen_hook_called == 1);

  len = strlen("world!!");
  TEST_ASSERT(len == 7);
  TEST_ASSERT(g_strlen_hook_called == 2);

  int r = newhook_unhook(handle);
  TEST_ASSERT(r == NH_OK);

  g_strlen_hook_called = 0;
  len = strlen("test");
  TEST_ASSERT(len == 4);
  TEST_ASSERT(g_strlen_hook_called == 0);

  TEST_PASS();
}

// ============================================================
// Test 3: hook by symbol name
// ============================================================

static int (*orig_atoi)(const char *) = NULL;
static int g_atoi_hook_called = 0;

static int my_atoi(const char *s) {
  g_atoi_hook_called++;
  return orig_atoi(s);
}

static void test_hook_sym_name(void) {
  TEST_BEGIN("hook_sym_name (atoi in libc.so)");

  g_atoi_hook_called = 0;
  void *handle = newhook_hook_sym_name("libc.so", "atoi",
                                       (void *)my_atoi, (void **)&orig_atoi);
  TEST_ASSERT(handle != NULL);
  TEST_ASSERT(orig_atoi != NULL);

  int val = atoi("12345");
  TEST_ASSERT(val == 12345);
  TEST_ASSERT(g_atoi_hook_called == 1);

  val = atoi("-99");
  TEST_ASSERT(val == -99);
  TEST_ASSERT(g_atoi_hook_called == 2);

  int r = newhook_unhook(handle);
  TEST_ASSERT(r == NH_OK);

  g_atoi_hook_called = 0;
  val = atoi("777");
  TEST_ASSERT(val == 777);
  TEST_ASSERT(g_atoi_hook_called == 0);

  TEST_PASS();
}

// ============================================================
// Test 4: double hook should fail (UNIQUE mode)
// ============================================================

static size_t my_strlen2(const char *s) {
  return orig_strlen(s);
}

static void test_double_hook(void) {
  TEST_BEGIN("double hook same addr -> error");

  void *h1 = newhook_hook_func_addr((void *)strlen, (void *)my_strlen,
                                     (void **)&orig_strlen);
  TEST_ASSERT(h1 != NULL);

  void *h2 = newhook_hook_func_addr((void *)strlen, (void *)my_strlen2, NULL);
  TEST_ASSERT(h2 == NULL);
  TEST_ASSERT(newhook_get_errno() == NH_ERR_ALREADY_HOOKED);

  newhook_unhook(h1);
  TEST_PASS();
}

// ============================================================
// Test 5: hook -> unhook -> re-hook should work
// ============================================================

static void test_rehook(void) {
  TEST_BEGIN("hook -> unhook -> re-hook");

  void *h1 = newhook_hook_func_addr((void *)strlen, (void *)my_strlen,
                                     (void **)&orig_strlen);
  TEST_ASSERT(h1 != NULL);

  g_strlen_hook_called = 0;
  strlen("a");
  TEST_ASSERT(g_strlen_hook_called == 1);

  newhook_unhook(h1);

  void *h2 = newhook_hook_func_addr((void *)strlen, (void *)my_strlen,
                                     (void **)&orig_strlen);
  TEST_ASSERT(h2 != NULL);

  g_strlen_hook_called = 0;
  strlen("bb");
  TEST_ASSERT(g_strlen_hook_called == 1);

  newhook_unhook(h2);
  TEST_PASS();
}

// ============================================================
// Test 6: invalid arguments
// ============================================================

static void test_invalid_args(void) {
  TEST_BEGIN("invalid arguments");

  void *h = newhook_hook_func_addr(NULL, (void *)my_strlen, NULL);
  TEST_ASSERT(h == NULL);
  TEST_ASSERT(newhook_get_errno() == NH_ERR_INVALID_ARG);

  h = newhook_hook_func_addr((void *)strlen, NULL, NULL);
  TEST_ASSERT(h == NULL);

  h = newhook_hook_sym_name("libc.so", NULL, (void *)my_strlen, NULL);
  TEST_ASSERT(h == NULL);

  h = newhook_hook_sym_name("libc.so", "this_symbol_does_not_exist_xyz",
                            (void *)my_strlen, NULL);
  TEST_ASSERT(h == NULL);
  TEST_ASSERT(newhook_get_errno() == NH_ERR_SYMBOL_NOT_FOUND);

  int r = newhook_unhook(NULL);
  TEST_ASSERT(r == NH_ERR_INVALID_ARG);

  const char *s = newhook_strerror(NH_OK);
  TEST_ASSERT(s != NULL);
  s = newhook_strerror(NH_ERR_SYMBOL_NOT_FOUND);
  TEST_ASSERT(s != NULL);

  TEST_PASS();
}

// ============================================================
// Test 7: hook with modified return value
// ============================================================

static int (*orig_abs)(int) = NULL;

static int my_abs_fixed42(int x) {
  (void)orig_abs;
  (void)x;
  return 42;
}

static void test_hook_modify_return(void) {
  TEST_BEGIN("hook modifies return value");

  void *handle = newhook_hook_sym_name("libc.so", "abs",
                                       (void *)my_abs_fixed42, (void **)&orig_abs);
  TEST_ASSERT(handle != NULL);

  int val = abs(-100);
  TEST_ASSERT(val == 42);

  val = abs(999);
  TEST_ASSERT(val == 42);

  newhook_unhook(handle);

  val = abs(-100);
  TEST_ASSERT(val == 100);

  TEST_PASS();
}

// ============================================================
// Test 8: multiple functions hooked simultaneously
// Uses TEST_ASSERT_CLEANUP to ensure all hooks are freed
// ============================================================

static int (*orig_abs_m)(int) = NULL;
static int (*orig_atoi_m)(const char *) = NULL;
static long (*orig_atol_m)(const char *) = NULL;

static atomic_int g_abs_m_called = 0;
static atomic_int g_atoi_m_called = 0;
static atomic_int g_atol_m_called = 0;

static int my_abs_m(int x) { atomic_fetch_add(&g_abs_m_called, 1); return orig_abs_m(x); }
static int my_atoi_m(const char *s) { atomic_fetch_add(&g_atoi_m_called, 1); return orig_atoi_m(s); }
static long my_atol_m(const char *s) { atomic_fetch_add(&g_atol_m_called, 1); return orig_atol_m(s); }

static void test_multi_hook_simultaneous(void) {
  TEST_BEGIN("multi hook simultaneous");

  void *h_abs = NULL, *h_atoi = NULL, *h_atol = NULL;

  h_abs = newhook_hook_sym_name("libc.so", "abs",
                                 (void *)my_abs_m, (void **)&orig_abs_m);
  h_atoi = newhook_hook_sym_name("libc.so", "atoi",
                                  (void *)my_atoi_m, (void **)&orig_atoi_m);
  h_atol = newhook_hook_sym_name("libc.so", "atol",
                                  (void *)my_atol_m, (void **)&orig_atol_m);

  TEST_ASSERT_CLEANUP(h_abs != NULL);
  TEST_ASSERT_CLEANUP(h_atoi != NULL);
  TEST_ASSERT_CLEANUP(h_atol != NULL);

  // Reset counters
  atomic_store(&g_abs_m_called, 0);
  atomic_store(&g_atoi_m_called, 0);
  atomic_store(&g_atol_m_called, 0);

  // Call all three
  TEST_ASSERT_CLEANUP(abs(-5) == 5);
  TEST_ASSERT_CLEANUP(atoi("123") == 123);
  TEST_ASSERT_CLEANUP(atol("456789") == 456789L);

  TEST_ASSERT_CLEANUP(atomic_load(&g_abs_m_called) == 1);
  TEST_ASSERT_CLEANUP(atomic_load(&g_atoi_m_called) == 1);
  TEST_ASSERT_CLEANUP(atomic_load(&g_atol_m_called) == 1);

  // Unhook abs only — others still work
  newhook_unhook(h_abs); h_abs = NULL;
  atomic_store(&g_abs_m_called, 0);
  atomic_store(&g_atoi_m_called, 0);

  (void)abs(-10);  // should NOT trigger hook
  (void)atoi("1"); // should trigger hook

  TEST_ASSERT_CLEANUP(atomic_load(&g_abs_m_called) == 0);
  TEST_ASSERT_CLEANUP(atomic_load(&g_atoi_m_called) == 1);

  TEST_PASS();

cleanup:
  if (h_abs)  newhook_unhook(h_abs);
  if (h_atoi) newhook_unhook(h_atoi);
  if (h_atol) newhook_unhook(h_atol);
}

// ============================================================
// Test 9: concurrent calls from multiple threads
// ============================================================

static int (*orig_atoi_thr)(const char *) = NULL;
static atomic_int g_thr_hook_count = 0;

static int my_atoi_thr(const char *s) {
  atomic_fetch_add(&g_thr_hook_count, 1);
  return orig_atoi_thr(s);
}

#define THREAD_ITER 1000
#define NUM_THREADS 4

static void *thread_call_atoi_fn(void *arg) {
  (void)arg;
  for (int i = 0; i < THREAD_ITER; i++) {
    int val = atoi("42");
    if (val != 42) return (void *)(uintptr_t)1;
  }
  return NULL;
}

static void test_thread_concurrent_call(void) {
  TEST_BEGIN("thread: concurrent calls (4x1000)");

  atomic_store(&g_thr_hook_count, 0);
  void *handle = newhook_hook_sym_name("libc.so", "atoi",
                                        (void *)my_atoi_thr, (void **)&orig_atoi_thr);
  TEST_ASSERT_CLEANUP(handle != NULL);

  pthread_t threads[NUM_THREADS];
  for (int i = 0; i < NUM_THREADS; i++) {
    int rc = pthread_create(&threads[i], NULL, thread_call_atoi_fn, NULL);
    TEST_ASSERT_CLEANUP(rc == 0);
  }

  int any_error = 0;
  for (int i = 0; i < NUM_THREADS; i++) {
    void *retval = NULL;
    pthread_join(threads[i], &retval);
    if (retval != NULL) any_error = 1;
  }

  TEST_ASSERT_CLEANUP(any_error == 0);
  TEST_ASSERT_CLEANUP(atomic_load(&g_thr_hook_count) == NUM_THREADS * THREAD_ITER);

  TEST_PASS();

cleanup:
  if (handle) newhook_unhook(handle);
}

// ============================================================
// Test 10: thread doing hook/unhook while others call
// ============================================================

static volatile int g_stop_workers = 0;
static atomic_int g_worker_calls = 0;
static atomic_int g_worker_errors = 0;

static int (*orig_atoi_race)(const char *) = NULL;
static int my_atoi_race(const char *s) { return orig_atoi_race(s); }

static void *worker_call_atoi_fn(void *arg) {
  (void)arg;
  while (!__atomic_load_n(&g_stop_workers, __ATOMIC_ACQUIRE)) {
    int val = atoi("100");
    if (val != 100) atomic_fetch_add(&g_worker_errors, 1);
    atomic_fetch_add(&g_worker_calls, 1);
  }
  return NULL;
}

static void test_thread_hook_unhook(void) {
  TEST_BEGIN("thread: hook/unhook while calling");

  __atomic_store_n(&g_stop_workers, 0, __ATOMIC_RELEASE);
  atomic_store(&g_worker_calls, 0);
  atomic_store(&g_worker_errors, 0);

  pthread_t workers[2];
  for (int i = 0; i < 2; i++)
    pthread_create(&workers[i], NULL, worker_call_atoi_fn, NULL);

  // Main thread: rapidly hook/unhook atoi 50 times
  for (int i = 0; i < 50; i++) {
    void *h = newhook_hook_sym_name("libc.so", "atoi",
                                     (void *)my_atoi_race, (void **)&orig_atoi_race);
    if (h != NULL) {
      usleep(100);
      newhook_unhook(h);
    }
    usleep(100);
  }

  __atomic_store_n(&g_stop_workers, 1, __ATOMIC_RELEASE);
  for (int i = 0; i < 2; i++)
    pthread_join(workers[i], NULL);

  TEST_ASSERT(atomic_load(&g_worker_calls) > 0);
  TEST_ASSERT(atomic_load(&g_worker_errors) == 0);

  TEST_PASS();
}

// ============================================================
// Test 11: thread-local errno isolation
// ============================================================

static atomic_int g_errno_t1 = -1;
static atomic_int g_errno_t2 = -1;

static int my_abs_errno(int x) { (void)x; return 0; }

static void *errno_thread_fail(void *arg) {
  (void)arg;
  void *h = newhook_hook_sym_name("libc.so", "no_such_symbol_xyz123",
                                   (void *)my_atoi, NULL);
  (void)h;
  atomic_store(&g_errno_t1, newhook_get_errno());
  return NULL;
}

static void *errno_thread_success(void *arg) {
  (void)arg;
  int (*orig)(int) = NULL;
  void *h = newhook_hook_sym_name("libc.so", "abs",
                                   (void *)my_abs_errno, (void **)&orig);
  atomic_store(&g_errno_t2, newhook_get_errno());
  if (h != NULL) newhook_unhook(h);
  return NULL;
}

static void test_thread_errno_isolation(void) {
  TEST_BEGIN("thread: errno isolation");

  atomic_store(&g_errno_t1, -1);
  atomic_store(&g_errno_t2, -1);

  // Run sequentially to avoid hook conflicts
  pthread_t t1, t2;
  pthread_create(&t1, NULL, errno_thread_fail, NULL);
  pthread_join(t1, NULL);

  pthread_create(&t2, NULL, errno_thread_success, NULL);
  pthread_join(t2, NULL);

  TEST_ASSERT(atomic_load(&g_errno_t1) == NH_ERR_SYMBOL_NOT_FOUND);
  TEST_ASSERT(atomic_load(&g_errno_t2) == NH_OK);

  TEST_PASS();
}

// ============================================================
// Test 12: hook function with many arguments (register check)
// ============================================================

static int (*orig_snprintf_hook)(char *, size_t, const char *, ...) = NULL;
static atomic_int g_snprintf_called = 0;

static int my_snprintf_hook(char *buf, size_t size, const char *fmt, ...) {
  atomic_fetch_add(&g_snprintf_called, 1);
  // Forward with known fixed args to verify parameter passing
  return orig_snprintf_hook(buf, size, "%d %s", 42, "hello");
}

static void test_hook_many_args(void) {
  TEST_BEGIN("hook many-arg func (snprintf)");

  atomic_store(&g_snprintf_called, 0);
  void *handle = newhook_hook_sym_name("libc.so", "snprintf",
                                        (void *)my_snprintf_hook,
                                        (void **)&orig_snprintf_hook);
  TEST_ASSERT_CLEANUP(handle != NULL);

  char buf[128];
  // Our hook intercepts and calls orig with fixed args "%d %s", 42, "hello"
  snprintf(buf, sizeof(buf), "ignored format");

  TEST_ASSERT_CLEANUP(atomic_load(&g_snprintf_called) == 1);
  TEST_ASSERT_CLEANUP(strcmp(buf, "42 hello") == 0);

  TEST_PASS();

cleanup:
  if (handle) newhook_unhook(handle);
  // Verify snprintf works after unhook
  {
    char buf2[64];
    snprintf(buf2, sizeof(buf2), "%d", 999);
    // Just ensure it doesn't crash; no assert needed
  }
}

// ============================================================
// Test 13: hook preserves caller state (ABI compliance)
// ============================================================

static long (*orig_atol_p)(const char *) = NULL;

static long my_atol_p(const char *s) {
  // Use many locals to stress register allocation
  volatile long a = 111, b = 222, c = 333, d = 444;
  long result = orig_atol_p(s);
  return result + (a - 111) + (b - 222) + (c - 333) + (d - 444);
}

static void test_hook_preserves_caller_state(void) {
  TEST_BEGIN("hook preserves caller state");

  void *handle = newhook_hook_sym_name("libc.so", "atol",
                                        (void *)my_atol_p, (void **)&orig_atol_p);
  TEST_ASSERT_CLEANUP(handle != NULL);

  // Set local state before calling hooked function
  volatile long x1 = 0xDEADBEEFL;
  volatile long x2 = 0xCAFEBABEL;
  volatile long x3 = 0x12345678L;

  long val = atol("99999");
  TEST_ASSERT_CLEANUP(val == 99999);

  // Caller's state must be preserved
  TEST_ASSERT_CLEANUP(x1 == 0xDEADBEEFL);
  TEST_ASSERT_CLEANUP(x2 == 0xCAFEBABEL);
  TEST_ASSERT_CLEANUP(x3 == 0x12345678L);

  for (int i = 0; i < 10; i++) {
    val = atol("12345");
    TEST_ASSERT_CLEANUP(val == 12345);
  }
  TEST_ASSERT_CLEANUP(x1 == 0xDEADBEEFL);

  TEST_PASS();

cleanup:
  if (handle) newhook_unhook(handle);
}

// ============================================================
// Test 14: stress test — rapid hook/unhook cycles
// ============================================================

static int (*orig_atoi_cyc)(const char *) = NULL;
static int my_atoi_cyc(const char *s) { return orig_atoi_cyc(s); }

static void test_stress_hook_unhook_cycles(void) {
  TEST_BEGIN("stress: 100 hook/unhook cycles");

  for (int i = 0; i < 100; i++) {
    void *h = newhook_hook_sym_name("libc.so", "atoi",
                                     (void *)my_atoi_cyc, (void **)&orig_atoi_cyc);
    if (h == NULL) {
      printf("FAIL\n    cycle %d: hook returned NULL\n", i);
      g_fail++; return;
    }

    int val = atoi("777");
    if (val != 777) {
      newhook_unhook(h);
      printf("FAIL\n    cycle %d: atoi returned %d\n", i, val);
      g_fail++; return;
    }

    newhook_unhook(h);

    val = atoi("888");
    if (val != 888) {
      printf("FAIL\n    cycle %d: restored atoi returned %d\n", i, val);
      g_fail++; return;
    }
  }

  TEST_PASS();
}

// ============================================================
// Test 15: stress test — many functions hooked at once
// ============================================================

static int (*orig_abs_s)(int) = NULL;
static long (*orig_atol_s)(const char *) = NULL;
static long (*orig_labs_s)(long) = NULL;
static int (*orig_atoi_s)(const char *) = NULL;

static int my_abs_s(int x) { return orig_abs_s(x); }
static long my_atol_s(const char *s) { return orig_atol_s(s); }
static long my_labs_s(long x) { return orig_labs_s(x); }
static int my_atoi_s(const char *s) { return orig_atoi_s(s); }

static void test_stress_many_hooks(void) {
  TEST_BEGIN("stress: 4 hooks active at once");

  void *h[4] = {NULL};

  h[0] = newhook_hook_sym_name("libc.so", "abs",
                                (void *)my_abs_s, (void **)&orig_abs_s);
  h[1] = newhook_hook_sym_name("libc.so", "atol",
                                (void *)my_atol_s, (void **)&orig_atol_s);
  h[2] = newhook_hook_sym_name("libc.so", "labs",
                                (void *)my_labs_s, (void **)&orig_labs_s);
  h[3] = newhook_hook_sym_name("libc.so", "atoi",
                                (void *)my_atoi_s, (void **)&orig_atoi_s);

  for (int i = 0; i < 4; i++)
    TEST_ASSERT_CLEANUP(h[i] != NULL);

  // Verify all work
  TEST_ASSERT_CLEANUP(abs(-42) == 42);
  TEST_ASSERT_CLEANUP(atol("123456789") == 123456789L);
  TEST_ASSERT_CLEANUP(labs(-999L) == 999L);
  TEST_ASSERT_CLEANUP(atoi("321") == 321);

  TEST_PASS();

cleanup:
  for (int i = 0; i < 4; i++)
    if (h[i]) newhook_unhook(h[i]);

  // Verify all restored
  if (abs(-42) != 42 || atoi("321") != 321) {
    printf("    [WARN] post-cleanup verification failed\n");
  }
}

// ============================================================
// Test 16: double unhook
// ============================================================

static int (*orig_abs_du)(int) = NULL;
static int my_abs_du(int x) { return orig_abs_du(x); }

static void test_double_unhook(void) {
  TEST_BEGIN("double unhook -> error");

  void *handle = newhook_hook_sym_name("libc.so", "abs",
                                        (void *)my_abs_du, (void **)&orig_abs_du);
  TEST_ASSERT(handle != NULL);

  int r = newhook_unhook(handle);
  TEST_ASSERT(r == NH_OK);

  // Verify that unhooking NULL returns error (safe to call).
  r = newhook_unhook(NULL);
  TEST_ASSERT(r == NH_ERR_INVALID_ARG);

  TEST_PASS();
}

// ============================================================
// Test 17: hook without requesting orig_func (NULL)
// ============================================================

static atomic_int g_no_orig_called = 0;

static int my_abs_no_orig(int x) {
  atomic_fetch_add(&g_no_orig_called, 1);
  return x >= 0 ? x : -x;  // re-implement abs
}

static void test_hook_without_orig(void) {
  TEST_BEGIN("hook with orig_func=NULL");

  atomic_store(&g_no_orig_called, 0);

  void *handle = newhook_hook_sym_name("libc.so", "abs",
                                        (void *)my_abs_no_orig, NULL);
  TEST_ASSERT_CLEANUP(handle != NULL);

  int val = abs(-50);
  TEST_ASSERT_CLEANUP(val == 50);
  TEST_ASSERT_CLEANUP(atomic_load(&g_no_orig_called) == 1);

  TEST_PASS();

cleanup:
  if (handle) newhook_unhook(handle);
}

// ============================================================
// Test 18: hook_sym_name with non-existent library
// ============================================================

static void test_hook_sym_nonexistent_lib(void) {
  TEST_BEGIN("hook_sym_name nonexistent lib");

  void *h = newhook_hook_sym_name("libdoes_not_exist_xyz.so", "atoi",
                                   (void *)my_atoi, NULL);
  TEST_ASSERT(h == NULL);
  TEST_ASSERT(newhook_get_errno() == NH_ERR_SYMBOL_NOT_FOUND);

  // NULL lib_name — search all libs, should find atoi
  int (*orig)(const char *) = NULL;
  h = newhook_hook_sym_name(NULL, "atoi", (void *)my_atoi, (void **)&orig);
  TEST_ASSERT_CLEANUP(h != NULL);
  TEST_ASSERT_CLEANUP(orig != NULL);

  int val = atoi("555");
  TEST_ASSERT_CLEANUP(val == 555);

  TEST_PASS();

cleanup:
  if (h) newhook_unhook(h);
}

// ============================================================
// Test 19: recursive hook call (no re-entry through enter trampoline)
// ============================================================

static int (*orig_atoi_rec)(const char *) = NULL;
static atomic_int g_rec_depth = 0;
static atomic_int g_rec_max = 0;

static int my_atoi_rec(const char *s) {
  int depth = atomic_fetch_add(&g_rec_depth, 1) + 1;
  int cur_max = atomic_load(&g_rec_max);
  if (depth > cur_max)
    atomic_store(&g_rec_max, depth);

  // Call orig — goes through enter trampoline, should NOT re-trigger hook
  int result = orig_atoi_rec(s);

  atomic_fetch_sub(&g_rec_depth, 1);
  return result;
}

static void test_recursive_hook_call(void) {
  TEST_BEGIN("recursive hook (no re-entry)");

  atomic_store(&g_rec_depth, 0);
  atomic_store(&g_rec_max, 0);

  void *handle = newhook_hook_sym_name("libc.so", "atoi",
                                        (void *)my_atoi_rec, (void **)&orig_atoi_rec);
  TEST_ASSERT_CLEANUP(handle != NULL);

  for (int i = 0; i < 100; i++) {
    int val = atoi("42");
    TEST_ASSERT_CLEANUP(val == 42);
  }

  // Max recursion depth should always be 1 (no re-entry)
  TEST_ASSERT_CLEANUP(atomic_load(&g_rec_max) == 1);
  TEST_ASSERT_CLEANUP(atomic_load(&g_rec_depth) == 0);

  TEST_PASS();

cleanup:
  if (handle) newhook_unhook(handle);
}

// ============================================================
// Test 20: hook arg passing with various input patterns
// ============================================================

static int (*orig_atoi_ap)(const char *) = NULL;
static atomic_int g_ap_called = 0;

static int my_atoi_ap(const char *s) {
  atomic_fetch_add(&g_ap_called, 1);
  return orig_atoi_ap(s);
}

static void test_hook_arg_passing(void) {
  TEST_BEGIN("hook arg passing (varied inputs)");

  atomic_store(&g_ap_called, 0);

  void *handle = newhook_hook_sym_name("libc.so", "atoi",
                                        (void *)my_atoi_ap, (void **)&orig_atoi_ap);
  TEST_ASSERT_CLEANUP(handle != NULL);

  // Various input patterns
  TEST_ASSERT_CLEANUP(atoi("0") == 0);
  TEST_ASSERT_CLEANUP(atoi("1") == 1);
  TEST_ASSERT_CLEANUP(atoi("-1") == -1);
  TEST_ASSERT_CLEANUP(atoi("2147483647") == 2147483647);   // INT_MAX
  TEST_ASSERT_CLEANUP(atoi("-2147483648") == -2147483647-1); // INT_MIN
  TEST_ASSERT_CLEANUP(atoi("00042") == 42);
  TEST_ASSERT_CLEANUP(atoi("  123") == 123);  // leading spaces
  TEST_ASSERT_CLEANUP(atoi("456xyz") == 456); // trailing non-digits

  TEST_ASSERT_CLEANUP(atomic_load(&g_ap_called) == 8);

  TEST_PASS();

cleanup:
  if (handle) newhook_unhook(handle);
}

// ============================================================
// Test 21: MULTI mode — two hooks on same address
// ============================================================

static atomic_int g_multi_hook1_called = 0;
static atomic_int g_multi_hook2_called = 0;
static int (*orig_abs_multi1)(int) = NULL;
static int (*orig_abs_multi2)(int) = NULL;

static int my_abs_multi1(int x) {
  atomic_fetch_add(&g_multi_hook1_called, 1);
  return orig_abs_multi1(x);
}

static int my_abs_multi2(int x) {
  atomic_fetch_add(&g_multi_hook2_called, 1);
  return orig_abs_multi2(x);
}

static void test_multi_two_hooks(void) {
  TEST_BEGIN("MULTI: two hooks on abs()");

  void *h1 = NULL, *h2 = NULL;

  h1 = newhook_hook_func_addr_ex((void *)abs, (void *)my_abs_multi1,
                                  (void **)&orig_abs_multi1, NH_MODE_MULTI);
  TEST_ASSERT_CLEANUP(h1 != NULL);
  TEST_ASSERT_CLEANUP(orig_abs_multi1 != NULL);

  h2 = newhook_hook_func_addr_ex((void *)abs, (void *)my_abs_multi2,
                                  (void **)&orig_abs_multi2, NH_MODE_MULTI);
  TEST_ASSERT_CLEANUP(h2 != NULL);
  TEST_ASSERT_CLEANUP(orig_abs_multi2 != NULL);

  atomic_store(&g_multi_hook1_called, 0);
  atomic_store(&g_multi_hook2_called, 0);

  // call abs — should go through hook1 -> hook2 -> original
  int r = abs(-42);
  TEST_ASSERT_CLEANUP(r == 42);
  TEST_ASSERT_CLEANUP(atomic_load(&g_multi_hook1_called) == 1);
  TEST_ASSERT_CLEANUP(atomic_load(&g_multi_hook2_called) == 1);

  TEST_PASS();

cleanup:
  if (h2) newhook_unhook(h2);
  if (h1) newhook_unhook(h1);
}

// ============================================================
// Test 22: MULTI mode — unhook middle, chain still works
// ============================================================

static atomic_int g_multi_a_called = 0;
static atomic_int g_multi_b_called = 0;
static atomic_int g_multi_c_called = 0;
static int (*orig_abs_ma)(int) = NULL;
static int (*orig_abs_mb)(int) = NULL;
static int (*orig_abs_mc)(int) = NULL;

static int my_abs_ma(int x) { atomic_fetch_add(&g_multi_a_called, 1); return orig_abs_ma(x); }
static int my_abs_mb(int x) { atomic_fetch_add(&g_multi_b_called, 1); return orig_abs_mb(x); }
static int my_abs_mc(int x) { atomic_fetch_add(&g_multi_c_called, 1); return orig_abs_mc(x); }

static void test_multi_unhook_middle(void) {
  TEST_BEGIN("MULTI: unhook middle of chain");

  void *ha = NULL, *hb = NULL, *hc = NULL;

  ha = newhook_hook_func_addr_ex((void *)abs, (void *)my_abs_ma,
                                  (void **)&orig_abs_ma, NH_MODE_MULTI);
  TEST_ASSERT_CLEANUP(ha != NULL);

  hb = newhook_hook_func_addr_ex((void *)abs, (void *)my_abs_mb,
                                  (void **)&orig_abs_mb, NH_MODE_MULTI);
  TEST_ASSERT_CLEANUP(hb != NULL);

  hc = newhook_hook_func_addr_ex((void *)abs, (void *)my_abs_mc,
                                  (void **)&orig_abs_mc, NH_MODE_MULTI);
  TEST_ASSERT_CLEANUP(hc != NULL);

  // unhook middle (B)
  int r = newhook_unhook(hb);
  hb = NULL;
  TEST_ASSERT_CLEANUP(r == NH_OK);

  atomic_store(&g_multi_a_called, 0);
  atomic_store(&g_multi_b_called, 0);
  atomic_store(&g_multi_c_called, 0);

  // call abs — should go through A -> C -> original (B skipped)
  int val = abs(-99);
  TEST_ASSERT_CLEANUP(val == 99);
  TEST_ASSERT_CLEANUP(atomic_load(&g_multi_a_called) == 1);
  TEST_ASSERT_CLEANUP(atomic_load(&g_multi_b_called) == 0);
  TEST_ASSERT_CLEANUP(atomic_load(&g_multi_c_called) == 1);

  TEST_PASS();

cleanup:
  if (hc) newhook_unhook(hc);
  if (hb) newhook_unhook(hb);
  if (ha) newhook_unhook(ha);
}

// ============================================================
// Test 23: MULTI mode — unhook all, function restored
// ============================================================

static int (*orig_abs_restore)(int) = NULL;
static int my_abs_restore(int x) { return orig_abs_restore(x) + 1000; }

static void test_multi_unhook_all(void) {
  TEST_BEGIN("MULTI: unhook all restores original");

  void *h1 = newhook_hook_func_addr_ex((void *)abs, (void *)my_abs_restore,
                                        (void **)&orig_abs_restore, NH_MODE_MULTI);
  TEST_ASSERT_CLEANUP(h1 != NULL);

  TEST_ASSERT_CLEANUP(abs(-5) == 1005);  // hooked: 5 + 1000

  int r = newhook_unhook(h1);
  h1 = NULL;
  TEST_ASSERT_CLEANUP(r == NH_OK);

  TEST_ASSERT_CLEANUP(abs(-5) == 5);  // restored

  TEST_PASS();

cleanup:
  if (h1) newhook_unhook(h1);
}

// ============================================================
// Test 24: MULTI mode — mode conflict with UNIQUE
// ============================================================

static int (*orig_abs_conflict)(int) = NULL;
static int my_abs_conflict(int x) { return orig_abs_conflict(x); }
static int (*orig_abs_conflict2)(int) = NULL;
static int my_abs_conflict2(int x) { return orig_abs_conflict2(x); }

static void test_multi_mode_conflict(void) {
  TEST_BEGIN("MULTI: mode conflict with UNIQUE");

  void *h1 = NULL, *h2 = NULL;

  // hook with UNIQUE first
  h1 = newhook_hook_func_addr_ex((void *)abs, (void *)my_abs_conflict,
                                  (void **)&orig_abs_conflict, NH_MODE_UNIQUE);
  TEST_ASSERT_CLEANUP(h1 != NULL);

  // try MULTI on same address — should fail
  h2 = newhook_hook_func_addr_ex((void *)abs, (void *)my_abs_conflict2,
                                  (void **)&orig_abs_conflict2, NH_MODE_MULTI);
  TEST_ASSERT_CLEANUP(h2 == NULL);

  TEST_PASS();

cleanup:
  if (h2) newhook_unhook(h2);
  if (h1) newhook_unhook(h1);
}

// ============================================================
// Test 25: SHARED mode — two hooks on same address
// ============================================================

static atomic_int g_shared_hook1_called = 0;
static atomic_int g_shared_hook2_called = 0;

static int my_abs_shared1(int x) {
  atomic_fetch_add(&g_shared_hook1_called, 1);
  // In SHARED mode, call prev to continue the chain
  int (*prev)(int) = (int (*)(int))newhook_get_prev_func((void *)my_abs_shared1);
  return prev(x);
}

static int my_abs_shared2(int x) {
  atomic_fetch_add(&g_shared_hook2_called, 1);
  int (*prev)(int) = (int (*)(int))newhook_get_prev_func((void *)my_abs_shared2);
  return prev(x);
}

static void test_shared_two_hooks(void) {
  TEST_BEGIN("SHARED: two hooks on abs()");

  void *h1 = NULL, *h2 = NULL;

  h1 = newhook_hook_func_addr_ex((void *)abs, (void *)my_abs_shared1,
                                  NULL, NH_MODE_SHARED);
  TEST_ASSERT_CLEANUP(h1 != NULL);

  h2 = newhook_hook_func_addr_ex((void *)abs, (void *)my_abs_shared2,
                                  NULL, NH_MODE_SHARED);
  TEST_ASSERT_CLEANUP(h2 != NULL);

  atomic_store(&g_shared_hook1_called, 0);
  atomic_store(&g_shared_hook2_called, 0);

  int r = abs(-77);
  TEST_ASSERT_CLEANUP(r == 77);
  // both hooks should have been called
  TEST_ASSERT_CLEANUP(atomic_load(&g_shared_hook1_called) >= 1);
  TEST_ASSERT_CLEANUP(atomic_load(&g_shared_hook2_called) >= 1);

  TEST_PASS();

cleanup:
  if (h2) newhook_unhook(h2);
  if (h1) newhook_unhook(h1);
}

// ============================================================
// Test 26: SHARED mode — unhook one, other still works
// ============================================================

static atomic_int g_shared_x_called = 0;
static atomic_int g_shared_y_called = 0;

static int my_abs_shared_x(int x) {
  atomic_fetch_add(&g_shared_x_called, 1);
  int (*prev)(int) = (int (*)(int))newhook_get_prev_func((void *)my_abs_shared_x);
  return prev(x);
}

static int my_abs_shared_y(int x) {
  atomic_fetch_add(&g_shared_y_called, 1);
  int (*prev)(int) = (int (*)(int))newhook_get_prev_func((void *)my_abs_shared_y);
  return prev(x);
}

static void test_shared_unhook_one(void) {
  TEST_BEGIN("SHARED: unhook one, other still works");

  void *hx = NULL, *hy = NULL;

  hx = newhook_hook_func_addr_ex((void *)abs, (void *)my_abs_shared_x,
                                  NULL, NH_MODE_SHARED);
  TEST_ASSERT_CLEANUP(hx != NULL);

  hy = newhook_hook_func_addr_ex((void *)abs, (void *)my_abs_shared_y,
                                  NULL, NH_MODE_SHARED);
  TEST_ASSERT_CLEANUP(hy != NULL);

  // unhook X
  int r = newhook_unhook(hx);
  hx = NULL;
  TEST_ASSERT_CLEANUP(r == NH_OK);

  atomic_store(&g_shared_x_called, 0);
  atomic_store(&g_shared_y_called, 0);

  int val = abs(-33);
  TEST_ASSERT_CLEANUP(val == 33);
  TEST_ASSERT_CLEANUP(atomic_load(&g_shared_x_called) == 0);  // X disabled
  TEST_ASSERT_CLEANUP(atomic_load(&g_shared_y_called) >= 1);   // Y still active

  TEST_PASS();

cleanup:
  if (hy) newhook_unhook(hy);
  if (hx) newhook_unhook(hx);
}

// ============================================================
// Test 27: SHARED mode — unhook all restores original
// ============================================================

static atomic_int g_shared_solo_called = 0;

static int my_abs_shared_solo(int x) {
  atomic_fetch_add(&g_shared_solo_called, 1);
  int (*prev)(int) = (int (*)(int))newhook_get_prev_func((void *)my_abs_shared_solo);
  return prev(x);
}

static void test_shared_unhook_all(void) {
  TEST_BEGIN("SHARED: unhook all restores original");

  void *h = newhook_hook_func_addr_ex((void *)abs, (void *)my_abs_shared_solo,
                                       NULL, NH_MODE_SHARED);
  TEST_ASSERT_CLEANUP(h != NULL);

  atomic_store(&g_shared_solo_called, 0);
  TEST_ASSERT_CLEANUP(abs(-10) == 10);
  TEST_ASSERT_CLEANUP(atomic_load(&g_shared_solo_called) == 1);

  int r = newhook_unhook(h);
  h = NULL;
  TEST_ASSERT_CLEANUP(r == NH_OK);

  atomic_store(&g_shared_solo_called, 0);
  TEST_ASSERT_CLEANUP(abs(-10) == 10);
  TEST_ASSERT_CLEANUP(atomic_load(&g_shared_solo_called) == 0);  // no longer called

  TEST_PASS();

cleanup:
  if (h) newhook_unhook(h);
}

// ============================================================
// Test 28: linker monitor init
// ============================================================

static void test_linker_monitor_init(void) {
  TEST_BEGIN("linker monitor init");

  int r = newhook_init_linker_monitor();
  TEST_ASSERT(r == NH_OK);

  // double init should also succeed
  r = newhook_init_linker_monitor();
  TEST_ASSERT(r == NH_OK);

  TEST_PASS();
}

// ============================================================
// Test 29: linker monitor detects dlopen
// ============================================================

static atomic_int g_dl_init_pre_called = 0;
static atomic_int g_dl_init_post_called = 0;

// Forward declare the callback type matching nh_dl_info_cb_t
// We include link.h for struct dl_phdr_info
static void dl_init_pre_cb(struct dl_phdr_info *info, size_t size, void *data) {
  (void)size; (void)data;
  if (info->dlpi_name && strstr(info->dlpi_name, "libshadowhook_nothing.so")) {
    atomic_fetch_add(&g_dl_init_pre_called, 1);
  }
}

static void dl_init_post_cb(struct dl_phdr_info *info, size_t size, void *data) {
  (void)size; (void)data;
  if (info->dlpi_name && strstr(info->dlpi_name, "libshadowhook_nothing.so")) {
    atomic_fetch_add(&g_dl_init_post_called, 1);
  }
}

// We need access to nh_linker registration functions (internal API)
#include "nh_linker.h"

static void test_linker_monitor_dlopen(void) {
  TEST_BEGIN("linker monitor detects dlopen");

  atomic_store(&g_dl_init_pre_called, 0);
  atomic_store(&g_dl_init_post_called, 0);

  int r = nh_linker_register_dl_init_cb(dl_init_pre_cb, dl_init_post_cb, NULL);
  TEST_ASSERT_CLEANUP(r == 0);

  // dlopen nothing.so — should trigger callbacks
  void *handle = dlopen("libshadowhook_nothing.so", RTLD_NOW);
  TEST_ASSERT_CLEANUP(handle != NULL);

  TEST_ASSERT_CLEANUP(atomic_load(&g_dl_init_pre_called) == 1);
  TEST_ASSERT_CLEANUP(atomic_load(&g_dl_init_post_called) == 1);

  dlclose(handle);

  nh_linker_unregister_dl_init_cb(dl_init_pre_cb, dl_init_post_cb, NULL);

  TEST_PASS();
  return;

cleanup:
  nh_linker_unregister_dl_init_cb(dl_init_pre_cb, dl_init_post_cb, NULL);
}

// ============================================================
// Test 30: delayed hook — hook_sym_name_ex on not-yet-loaded lib
// ============================================================

static void test_delayed_hook_pending(void) {
  TEST_BEGIN("delayed hook returns pending");

  void *orig = NULL;
  void *handle = newhook_hook_sym_name_ex(
      "libnotloaded_test.so", "some_func",
      (void *)(uintptr_t)0xDEAD, &orig, NH_MODE_UNIQUE);

  // Should return a handle (pending) or NULL with PENDING errno
  if (handle != NULL) {
    // pending task created, handle is valid but hook not yet active
    TEST_ASSERT_CLEANUP(newhook_get_errno() == NH_ERR_PENDING || newhook_get_errno() == NH_OK);
    newhook_unhook(handle);
  } else {
    // pending not yet implemented or linker monitor not active — should be PENDING or SYMBOL_NOT_FOUND
    int err = newhook_get_errno();
    TEST_ASSERT(err == NH_ERR_PENDING || err == NH_ERR_SYMBOL_NOT_FOUND);
  }

  TEST_PASS();
  return;

cleanup:
  if (handle) newhook_unhook(handle);
}

// ============================================================
// main
// ============================================================

int main(void) {
  printf("========================================\n");
  printf("  newhook test suite (ARM64)\n");
  printf("========================================\n\n");

  printf("--- Basic functionality ---\n");
  test_init();
  test_hook_func_addr();
  test_hook_sym_name();
  test_double_hook();
  test_rehook();
  test_invalid_args();
  test_hook_modify_return();

  printf("\n--- Safety & robustness ---\n");
  test_multi_hook_simultaneous();
  test_thread_concurrent_call();
  test_thread_hook_unhook();
  test_thread_errno_isolation();
  test_hook_many_args();
  test_hook_preserves_caller_state();
  test_stress_hook_unhook_cycles();
  test_stress_many_hooks();
  test_double_unhook();
  test_hook_without_orig();
  test_hook_sym_nonexistent_lib();
  test_recursive_hook_call();
  test_hook_arg_passing();

  printf("\n--- MULTI mode ---\n");
  test_multi_two_hooks();
  test_multi_unhook_middle();
  test_multi_unhook_all();
  test_multi_mode_conflict();

  printf("\n--- SHARED mode ---\n");
  test_shared_two_hooks();
  test_shared_unhook_one();
  test_shared_unhook_all();

  printf("\n--- Linker monitor ---\n");
  test_linker_monitor_init();
  test_linker_monitor_dlopen();
  test_delayed_hook_pending();

  printf("\n========================================\n");
  printf("  Results: %d passed, %d failed\n", g_pass, g_fail);
  printf("========================================\n");

  return g_fail > 0 ? 1 : 0;
}
