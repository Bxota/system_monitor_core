#include "../sysmon_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__) || defined(__linux__)
#include <sys/statvfs.h>
#endif

#define SYSMON_STORAGE_PATH_LEN 256

typedef struct storage_state {
  char path[SYSMON_STORAGE_PATH_LEN];
  uint64_t last_total_bytes;
  uint64_t last_free_bytes;
  uint64_t last_avail_bytes;
  uint64_t last_used_bytes;
  double last_used_percent;
  bool has_data;
} storage_state_t;

static void copy_path(char *dst, size_t dst_len, const char *src) {
  if (!dst || dst_len == 0) return;
  if (!src) {
    dst[0] = '\0';
    return;
  }
  snprintf(dst, dst_len, "%s", src);
}

static bool read_storage_stats(const char *path, uint64_t *out_total, uint64_t *out_free,
                               uint64_t *out_avail, char **out_error) {
#if defined(__APPLE__) || defined(__linux__)
  if (!path || !out_total || !out_free || !out_avail) return false;
  struct statvfs vfs;
  if (statvfs(path, &vfs) != 0) {
    char buf[256];
    snprintf(buf, sizeof(buf), "statvfs(%s) failed: %s", path, strerror(errno));
    sysmon_set_error(out_error, buf);
    return false;
  }
  const uint64_t block_size = vfs.f_frsize ? (uint64_t)vfs.f_frsize : (uint64_t)vfs.f_bsize;
  *out_total = (uint64_t)vfs.f_blocks * block_size;
  *out_free = (uint64_t)vfs.f_bfree * block_size;
  *out_avail = (uint64_t)vfs.f_bavail * block_size;
  return true;
#else
  (void)path;
  (void)out_total;
  (void)out_free;
  (void)out_avail;
  sysmon_set_error(out_error, "storage module not supported on this platform");
  return false;
#endif
}

static sysmon_result_t storage_create(const sysmon_ini_t *ini, const char *section,
                                      void **out_state, char **out_error) {
  if (!out_state) return SYSMON_ERR_INVALID_ARGUMENT;

  storage_state_t *st = (storage_state_t *)calloc(1, sizeof(*st));
  if (!st) return SYSMON_ERR_OUT_OF_MEMORY;

  const char *path = sysmon_ini_get(ini, section, "path");
  if (!path || !*path) path = "/";
  copy_path(st->path, sizeof(st->path), path);

  uint64_t total = 0, free_b = 0, avail = 0;
  char *err = NULL;
  if (!read_storage_stats(st->path, &total, &free_b, &avail, &err)) {
    sysmon_set_error(out_error, err ? err : "failed to read storage stats");
    free(err);
    free(st);
    return SYSMON_ERR_NOT_SUPPORTED;
  }
  free(err);

  st->has_data = false;
  *out_state = st;
  return SYSMON_OK;
}

static sysmon_result_t storage_poll(void *state, uint64_t now_ms, bool refresh_now,
                                    sysmon_snapshot_builder_t *builder, char **out_error) {
  (void)now_ms;
  storage_state_t *st = (storage_state_t *)state;
  if (!st || !builder) return SYSMON_ERR_INVALID_ARGUMENT;

  if (refresh_now || !st->has_data) {
    uint64_t total = 0, free_b = 0, avail = 0;
    char *err = NULL;
    if (!read_storage_stats(st->path, &total, &free_b, &avail, &err)) {
      sysmon_set_error(out_error, err ? err : "failed to read storage stats");
      free(err);
      return SYSMON_ERR_IO;
    }
    free(err);

    st->last_total_bytes = total;
    st->last_free_bytes = free_b;
    st->last_avail_bytes = avail;
    st->last_used_bytes = total >= free_b ? (total - free_b) : 0;
    st->last_used_percent =
        total > 0 ? (double)st->last_used_bytes * 100.0 / (double)total : 0.0;
    st->has_data = true;
  }

  sysmon_result_t rc = sysmon_snapshot_builder_add_string(builder, "storage.path", NULL, st->path);
  if (rc != SYSMON_OK) return rc;
  rc = sysmon_snapshot_builder_add_u64(builder, "storage.total_bytes", "B", st->last_total_bytes);
  if (rc != SYSMON_OK) return rc;
  rc = sysmon_snapshot_builder_add_u64(builder, "storage.used_bytes", "B", st->last_used_bytes);
  if (rc != SYSMON_OK) return rc;
  rc = sysmon_snapshot_builder_add_u64(builder, "storage.free_bytes", "B", st->last_free_bytes);
  if (rc != SYSMON_OK) return rc;
  rc = sysmon_snapshot_builder_add_u64(builder, "storage.available_bytes", "B", st->last_avail_bytes);
  if (rc != SYSMON_OK) return rc;
  rc = sysmon_snapshot_builder_add_double(builder, "storage.used_percent", "%", st->last_used_percent);
  if (rc != SYSMON_OK) return rc;
  return SYSMON_OK;
}

static void storage_destroy(void *state) { free(state); }

const sysmon_module_vtable_t *sysmon_storage_module(void) {
  static const sysmon_module_vtable_t vtable = {
      .name = "storage", .create = storage_create, .poll = storage_poll, .destroy = storage_destroy};
  return &vtable;
}
