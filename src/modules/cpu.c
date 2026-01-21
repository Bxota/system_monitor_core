#include "../sysmon_internal.h"

#include <stdio.h>
#include <stdlib.h>

#if defined(__APPLE__)
#include <mach/mach.h>
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <unistd.h>
#endif

typedef struct cpu_state {
  uint64_t last_total;
  uint64_t last_idle;
  double last_usage_percent;
  uint32_t core_count;
  bool has_prev;
} cpu_state_t;

static uint32_t detect_core_count(void) {
#if defined(__APPLE__)
  int ncpu = 0;
  size_t len = sizeof(ncpu);
  if (sysctlbyname("hw.ncpu", &ncpu, &len, NULL, 0) == 0 && ncpu > 0) return (uint32_t)ncpu;
  return 0;
#elif defined(__linux__)
  long n = sysconf(_SC_NPROCESSORS_ONLN);
  return n > 0 ? (uint32_t)n : 0;
#else
  return 0;
#endif
}

static bool read_cpu_ticks(uint64_t *out_total, uint64_t *out_idle, char **out_error) {
#if defined(__APPLE__)
  host_cpu_load_info_data_t load = {0};
  mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
  kern_return_t kr =
      host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, (host_info_t)&load, &count);
  if (kr != KERN_SUCCESS) {
    sysmon_set_error(out_error, "host_statistics(HOST_CPU_LOAD_INFO) failed");
    return false;
  }
  const uint64_t user = (uint64_t)load.cpu_ticks[CPU_STATE_USER];
  const uint64_t sys = (uint64_t)load.cpu_ticks[CPU_STATE_SYSTEM];
  const uint64_t idle = (uint64_t)load.cpu_ticks[CPU_STATE_IDLE];
  const uint64_t nice = (uint64_t)load.cpu_ticks[CPU_STATE_NICE];
  *out_idle = idle;
  *out_total = user + sys + idle + nice;
  return true;
#elif defined(__linux__)
  FILE *f = fopen("/proc/stat", "r");
  if (!f) {
    sysmon_set_error(out_error, "failed to open /proc/stat");
    return false;
  }
  char buf[512];
  if (!fgets(buf, (int)sizeof(buf), f)) {
    fclose(f);
    sysmon_set_error(out_error, "failed to read /proc/stat");
    return false;
  }
  fclose(f);

  unsigned long long user = 0, nice = 0, system = 0, idle = 0, iowait = 0, irq = 0, softirq = 0,
                     steal = 0;
  int scanned = sscanf(buf, "cpu %llu %llu %llu %llu %llu %llu %llu %llu", &user, &nice, &system,
                       &idle, &iowait, &irq, &softirq, &steal);
  if (scanned < 4) {
    sysmon_set_error(out_error, "unexpected /proc/stat format");
    return false;
  }
  const uint64_t idle_all = (uint64_t)idle + (uint64_t)iowait;
  const uint64_t total = (uint64_t)user + (uint64_t)nice + (uint64_t)system + (uint64_t)idle +
                         (uint64_t)iowait + (uint64_t)irq + (uint64_t)softirq + (uint64_t)steal;
  *out_idle = idle_all;
  *out_total = total;
  return true;
#else
  (void)out_total;
  (void)out_idle;
  sysmon_set_error(out_error, "cpu module not supported on this platform");
  return false;
#endif
}

static sysmon_result_t cpu_create(const sysmon_ini_t *ini, const char *section, void **out_state,
                                  char **out_error) {
  (void)ini;
  (void)section;
  if (!out_state) return SYSMON_ERR_INVALID_ARGUMENT;

  cpu_state_t *st = (cpu_state_t *)calloc(1, sizeof(*st));
  if (!st) return SYSMON_ERR_OUT_OF_MEMORY;
  st->core_count = detect_core_count();
  st->last_usage_percent = 0.0;
  *out_state = st;
  (void)out_error;
  return SYSMON_OK;
}

static sysmon_result_t cpu_poll(void *state, uint64_t now_ms, bool refresh_now,
                                sysmon_snapshot_builder_t *builder, char **out_error) {
  (void)now_ms;
  cpu_state_t *st = (cpu_state_t *)state;
  if (!st || !builder) return SYSMON_ERR_INVALID_ARGUMENT;

  if (refresh_now || !st->has_prev) {
    uint64_t total = 0, idle = 0;
    char *err = NULL;
    if (!read_cpu_ticks(&total, &idle, &err)) {
      sysmon_set_error(out_error, err ? err : "failed to read cpu ticks");
      free(err);
      return SYSMON_ERR_NOT_SUPPORTED;
    }
    free(err);

    if (st->has_prev) {
      const uint64_t total_delta = total - st->last_total;
      const uint64_t idle_delta = idle - st->last_idle;
      if (total_delta > 0 && idle_delta <= total_delta) {
        st->last_usage_percent = (double)(total_delta - idle_delta) * 100.0 / (double)total_delta;
      }
    } else {
      st->has_prev = true;
    }
    st->last_total = total;
    st->last_idle = idle;
  }

  sysmon_result_t rc =
      sysmon_snapshot_builder_add_double(builder, "cpu.usage_percent", "%", st->last_usage_percent);
  if (rc != SYSMON_OK) return rc;
  if (st->core_count > 0) {
    rc = sysmon_snapshot_builder_add_u64(builder, "cpu.core_count", NULL, st->core_count);
    if (rc != SYSMON_OK) return rc;
  }
  return SYSMON_OK;
}

static void cpu_destroy(void *state) { free(state); }

const sysmon_module_vtable_t *sysmon_cpu_module(void) {
  static const sysmon_module_vtable_t vtable = {
      .name = "cpu", .create = cpu_create, .poll = cpu_poll, .destroy = cpu_destroy};
  return &vtable;
}
