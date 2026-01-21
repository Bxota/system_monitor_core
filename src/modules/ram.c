#include "../sysmon_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#include <mach/mach.h>
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <unistd.h>
#endif

typedef struct ram_state {
  uint64_t total_bytes;
  uint64_t last_used_bytes;
  uint64_t last_free_bytes;
  double last_used_percent;
  bool has_data;
} ram_state_t;

static bool read_total_mem(uint64_t *out_total, char **out_error) {
#if defined(__APPLE__)
  uint64_t memsize = 0;
  size_t len = sizeof(memsize);
  if (sysctlbyname("hw.memsize", &memsize, &len, NULL, 0) != 0 || memsize == 0) {
    sysmon_set_error(out_error, "sysctlbyname(hw.memsize) failed");
    return false;
  }
  *out_total = memsize;
  return true;
#elif defined(__linux__)
  FILE *f = fopen("/proc/meminfo", "r");
  if (!f) {
    sysmon_set_error(out_error, "failed to open /proc/meminfo");
    return false;
  }
  char line[256];
  while (fgets(line, (int)sizeof(line), f)) {
    unsigned long long kb = 0;
    if (sscanf(line, "MemTotal: %llu kB", &kb) == 1) {
      fclose(f);
      *out_total = (uint64_t)kb * 1024ull;
      return true;
    }
  }
  fclose(f);
  sysmon_set_error(out_error, "MemTotal not found in /proc/meminfo");
  return false;
#else
  (void)out_total;
  sysmon_set_error(out_error, "ram module not supported on this platform");
  return false;
#endif
}

static bool read_mem_used_free(uint64_t total_bytes, uint64_t *out_used, uint64_t *out_free,
                               char **out_error) {
#if defined(__APPLE__)
  vm_size_t page_size = 0;
  if (host_page_size(mach_host_self(), &page_size) != KERN_SUCCESS || page_size == 0) {
    sysmon_set_error(out_error, "host_page_size failed");
    return false;
  }
  vm_statistics64_data_t vmstat = {0};
  mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
  if (host_statistics64(mach_host_self(), HOST_VM_INFO64, (host_info64_t)&vmstat, &count) !=
      KERN_SUCCESS) {
    sysmon_set_error(out_error, "host_statistics64(HOST_VM_INFO64) failed");
    return false;
  }

  uint64_t free_bytes = (uint64_t)vmstat.free_count * (uint64_t)page_size;
  if (free_bytes > total_bytes) free_bytes = 0;
  uint64_t used_bytes = total_bytes - free_bytes;
  *out_used = used_bytes;
  *out_free = free_bytes;
  return true;
#elif defined(__linux__)
  FILE *f = fopen("/proc/meminfo", "r");
  if (!f) {
    sysmon_set_error(out_error, "failed to open /proc/meminfo");
    return false;
  }
  unsigned long long mem_total_kb = 0, mem_free_kb = 0, mem_available_kb = 0;
  char line[256];
  while (fgets(line, (int)sizeof(line), f)) {
    unsigned long long kb = 0;
    if (sscanf(line, "MemTotal: %llu kB", &kb) == 1) mem_total_kb = kb;
    if (sscanf(line, "MemFree: %llu kB", &kb) == 1) mem_free_kb = kb;
    if (sscanf(line, "MemAvailable: %llu kB", &kb) == 1) mem_available_kb = kb;
  }
  fclose(f);
  uint64_t free_bytes = (uint64_t)(mem_available_kb ? mem_available_kb : mem_free_kb) * 1024ull;
  if (free_bytes > total_bytes) free_bytes = 0;
  uint64_t used_bytes = total_bytes - free_bytes;
  (void)mem_total_kb;
  *out_used = used_bytes;
  *out_free = free_bytes;
  return true;
#else
  (void)total_bytes;
  (void)out_used;
  (void)out_free;
  sysmon_set_error(out_error, "ram module not supported on this platform");
  return false;
#endif
}

static sysmon_result_t ram_create(const sysmon_ini_t *ini, const char *section, void **out_state,
                                  char **out_error) {
  (void)ini;
  (void)section;
  if (!out_state) return SYSMON_ERR_INVALID_ARGUMENT;
  ram_state_t *st = (ram_state_t *)calloc(1, sizeof(*st));
  if (!st) return SYSMON_ERR_OUT_OF_MEMORY;
  char *err = NULL;
  if (!read_total_mem(&st->total_bytes, &err)) {
    sysmon_set_error(out_error, err ? err : "failed to read total memory");
    free(err);
    free(st);
    return SYSMON_ERR_NOT_SUPPORTED;
  }
  free(err);
  *out_state = st;
  return SYSMON_OK;
}

static sysmon_result_t ram_poll(void *state, uint64_t now_ms, bool refresh_now,
                                sysmon_snapshot_builder_t *builder, char **out_error) {
  (void)now_ms;
  ram_state_t *st = (ram_state_t *)state;
  if (!st || !builder) return SYSMON_ERR_INVALID_ARGUMENT;

  if (refresh_now || !st->has_data) {
    uint64_t used = 0, free_b = 0;
    char *err = NULL;
    if (!read_mem_used_free(st->total_bytes, &used, &free_b, &err)) {
      sysmon_set_error(out_error, err ? err : "failed to read memory usage");
      free(err);
      return SYSMON_ERR_NOT_SUPPORTED;
    }
    free(err);
    st->last_used_bytes = used;
    st->last_free_bytes = free_b;
    st->last_used_percent =
        st->total_bytes > 0 ? (double)used * 100.0 / (double)st->total_bytes : 0.0;
    st->has_data = true;
  }

  sysmon_result_t rc =
      sysmon_snapshot_builder_add_u64(builder, "ram.total_bytes", "B", st->total_bytes);
  if (rc != SYSMON_OK) return rc;
  rc = sysmon_snapshot_builder_add_u64(builder, "ram.used_bytes", "B", st->last_used_bytes);
  if (rc != SYSMON_OK) return rc;
  rc = sysmon_snapshot_builder_add_u64(builder, "ram.free_bytes", "B", st->last_free_bytes);
  if (rc != SYSMON_OK) return rc;
  if (st->total_bytes > 0) {
    rc = sysmon_snapshot_builder_add_double(builder, "ram.used_percent", "%", st->last_used_percent);
    if (rc != SYSMON_OK) return rc;
  }
  return SYSMON_OK;
}

static void ram_destroy(void *state) { free(state); }

const sysmon_module_vtable_t *sysmon_ram_module(void) {
  static const sysmon_module_vtable_t vtable = {
      .name = "ram", .create = ram_create, .poll = ram_poll, .destroy = ram_destroy};
  return &vtable;
}
