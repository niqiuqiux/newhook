#include "nh_task.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "newhook.h"
#include "nh_linker.h"
#include "nh_log.h"
#include "nh_switch.h"
#include "nh_symbol.h"
#include "nh_util.h"

// ============================================================================
// Task structure
// ============================================================================

#define NH_TASK_MAGIC 0x4E485441  // "NHTA"

struct nh_task {
  uint32_t magic;                // NH_TASK_MAGIC — used to identify task handles
  char *lib_name;
  char *sym_name;
  uintptr_t new_func;
  void **orig_func;
  int mode;
  bool is_finished;
  nh_switch_handle_t *switch_handle;  // set when hook activates
  struct nh_task *next;
};

// ============================================================================
// Global state
// ============================================================================

static pthread_mutex_t g_tasks_lock = PTHREAD_MUTEX_INITIALIZER;
static nh_task_t *g_tasks = NULL;
static bool g_task_inited = false;

// ============================================================================
// dl_init callback — retry pending tasks when a library loads
// ============================================================================

static void task_dl_init_pre(struct dl_phdr_info *info, size_t size, void *data) {
  (void)size; (void)data;

  if (info->dlpi_name == NULL) return;

  pthread_mutex_lock(&g_tasks_lock);

  for (nh_task_t *task = g_tasks; task != NULL; task = task->next) {
    if (task->is_finished) continue;

    // check if this loaded library matches the task's lib_name
    if (!nh_util_match_lib_name(info->dlpi_name, task->lib_name)) continue;

    NH_LOG_I("task: library loaded, retrying hook: %s -> %s", task->lib_name, task->sym_name);

    // try to resolve symbol now
    nh_symbol_info_t sym_info;
    if (nh_symbol_find(task->lib_name, task->sym_name, &sym_info) != 0) {
      NH_LOG_W("task: symbol still not found: %s", task->sym_name);
      continue;
    }

    // install hook via switch
    nh_switch_handle_t *sh = nh_switch_hook(
        sym_info.addr, task->new_func, task->orig_func, task->mode, sym_info.size);

    if (sh) {
      task->switch_handle = sh;
      task->is_finished = true;
      NH_LOG_I("task: delayed hook activated: %s!%s @ %p",
               task->lib_name, task->sym_name, (void *)sym_info.addr);
    } else {
      NH_LOG_E("task: delayed hook install failed: %s!%s", task->lib_name, task->sym_name);
    }
  }

  pthread_mutex_unlock(&g_tasks_lock);
}

// ============================================================================
// Public API
// ============================================================================

int nh_task_init(void) {
  if (g_task_inited) return 0;

  int r = nh_linker_register_dl_init_cb(task_dl_init_pre, NULL, NULL);
  if (r != 0) return r;

  g_task_inited = true;
  NH_LOG_I("task: initialized");
  return 0;
}

nh_task_t *nh_task_create(const char *lib_name, const char *sym_name,
                          uintptr_t new_func, void **orig_func, int mode) {
  nh_task_t *task = calloc(1, sizeof(nh_task_t));
  if (!task) return NULL;

  task->magic = NH_TASK_MAGIC;
  task->lib_name = strdup(lib_name ? lib_name : "");
  task->sym_name = strdup(sym_name);
  task->new_func = new_func;
  task->orig_func = orig_func;
  task->mode = mode;
  task->is_finished = false;
  task->switch_handle = NULL;

  if (!task->lib_name || !task->sym_name) {
    free(task->lib_name);
    free(task->sym_name);
    free(task);
    return NULL;
  }

  pthread_mutex_lock(&g_tasks_lock);
  task->next = g_tasks;
  g_tasks = task;
  pthread_mutex_unlock(&g_tasks_lock);

  NH_LOG_I("task: created pending hook: %s!%s", task->lib_name, task->sym_name);
  return task;
}

int nh_task_destroy(nh_task_t *task) {
  if (!task) return NH_ERR_INVALID_ARG;

  pthread_mutex_lock(&g_tasks_lock);

  // remove from list
  if (g_tasks == task) {
    g_tasks = task->next;
  } else {
    for (nh_task_t *p = g_tasks; p; p = p->next) {
      if (p->next == task) {
        p->next = task->next;
        break;
      }
    }
  }

  pthread_mutex_unlock(&g_tasks_lock);

  // if hook was activated, unhook it
  int r = NH_OK;
  if (task->is_finished && task->switch_handle) {
    r = nh_switch_unhook(task->switch_handle);
  }

  free(task->lib_name);
  free(task->sym_name);
  free(task);
  return r;
}

int nh_task_is_task(void *handle) {
  if (!handle) return 0;
  nh_task_t *task = (nh_task_t *)handle;
  return task->magic == NH_TASK_MAGIC;
}

void *nh_task_get_switch_handle(nh_task_t *task) {
  if (!task || !task->is_finished) return NULL;
  return task->switch_handle;
}
