#include "../sysmon_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#if defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/ps/IOPowerSources.h>
#include <IOKit/ps/IOPSKeys.h>
#elif defined(__linux__)
#include <dirent.h>
#include <sys/stat.h>
#endif

typedef struct battery_state {
#if defined(__linux__)
  char base_path[256];
#endif
  double last_percent;
  int64_t last_is_charging;
  char last_status[32];
  bool has_data;
} battery_state_t;

static void set_default_status(battery_state_t *st) {
  st->last_percent = 0.0;
  st->last_is_charging = 0;
  snprintf(st->last_status, sizeof(st->last_status), "%s", "unknown");
}

#if defined(__linux__)
static bool file_exists(const char *path) {
  struct stat st;
  return stat(path, &st) == 0;
}

static bool detect_battery_path(char *out_base_path, size_t out_len, char **out_error) {
  const char *root = "/sys/class/power_supply";
  DIR *d = opendir(root);
  if (!d) {
    sysmon_set_error(out_error, "failed to open /sys/class/power_supply");
    return false;
  }
  struct dirent *de = NULL;
  while ((de = readdir(d)) != NULL) {
    if (strncmp(de->d_name, "BAT", 3) != 0) continue;
    char candidate[256];
    snprintf(candidate, sizeof(candidate), "%s/%s", root, de->d_name);
    char cap[320];
    snprintf(cap, sizeof(cap), "%s/capacity", candidate);
    if (file_exists(cap)) {
      snprintf(out_base_path, out_len, "%s", candidate);
      closedir(d);
      return true;
    }
  }
  closedir(d);
  sysmon_set_error(out_error, "no battery found under /sys/class/power_supply");
  return false;
}

static bool read_u32_file(const char *path, uint32_t *out_value) {
  FILE *f = fopen(path, "r");
  if (!f) return false;
  unsigned v = 0;
  int ok = fscanf(f, "%u", &v);
  fclose(f);
  if (ok != 1) return false;
  *out_value = v;
  return true;
}

static bool read_string_file(const char *path, char *out, size_t out_len) {
  FILE *f = fopen(path, "r");
  if (!f) return false;
  if (!fgets(out, (int)out_len, f)) {
    fclose(f);
    return false;
  }
  fclose(f);
  size_t n = strlen(out);
  while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r')) out[--n] = '\0';
  return true;
}
#endif

static sysmon_result_t battery_create(const sysmon_ini_t *ini, const char *section, void **out_state,
                                      char **out_error) {
  (void)ini;
  (void)section;
  if (!out_state) return SYSMON_ERR_INVALID_ARGUMENT;

  battery_state_t *st = (battery_state_t *)calloc(1, sizeof(*st));
  if (!st) return SYSMON_ERR_OUT_OF_MEMORY;
  set_default_status(st);

#if defined(__linux__)
  char *err = NULL;
  if (!detect_battery_path(st->base_path, sizeof(st->base_path), &err)) {
    sysmon_set_error(out_error, err ? err : "battery not detected");
    free(err);
    free(st);
    return SYSMON_ERR_NOT_SUPPORTED;
  }
  free(err);
#endif

#if defined(__APPLE__)
  CFTypeRef info = IOPSCopyPowerSourcesInfo();
  if (!info) {
    free(st);
    sysmon_set_error(out_error, "IOPSCopyPowerSourcesInfo failed");
    return SYSMON_ERR_NOT_SUPPORTED;
  }
  CFArrayRef sources = IOPSCopyPowerSourcesList(info);
  if (!sources || CFArrayGetCount(sources) == 0) {
    if (sources) CFRelease(sources);
    CFRelease(info);
    free(st);
    sysmon_set_error(out_error, "no battery power source available");
    return SYSMON_ERR_NOT_SUPPORTED;
  }
  CFRelease(sources);
  CFRelease(info);
#endif

  *out_state = st;
  return SYSMON_OK;
}

static sysmon_result_t battery_poll(void *state, uint64_t now_ms, bool refresh_now,
                                    sysmon_snapshot_builder_t *builder, char **out_error) {
  (void)now_ms;
  battery_state_t *st = (battery_state_t *)state;
  if (!st || !builder) return SYSMON_ERR_INVALID_ARGUMENT;

#if defined(__APPLE__) || defined(__linux__)
  if (refresh_now || !st->has_data) {
#if defined(__APPLE__)
  CFTypeRef info = IOPSCopyPowerSourcesInfo();
  if (!info) {
    sysmon_set_error(out_error, "IOPSCopyPowerSourcesInfo failed");
    return SYSMON_ERR_NOT_SUPPORTED;
  }
  CFArrayRef sources = IOPSCopyPowerSourcesList(info);
  if (!sources || CFArrayGetCount(sources) == 0) {
    if (sources) CFRelease(sources);
    CFRelease(info);
    sysmon_set_error(out_error, "no battery power source available");
    return SYSMON_ERR_NOT_SUPPORTED;
  }

  bool found = false;
  for (CFIndex i = 0; i < CFArrayGetCount(sources); i++) {
    CFTypeRef ps = CFArrayGetValueAtIndex(sources, i);
    CFDictionaryRef desc = IOPSGetPowerSourceDescription(info, ps);
    if (!desc) continue;

    CFNumberRef cur = (CFNumberRef)CFDictionaryGetValue(desc, CFSTR(kIOPSCurrentCapacityKey));
    CFNumberRef max = (CFNumberRef)CFDictionaryGetValue(desc, CFSTR(kIOPSMaxCapacityKey));
    CFBooleanRef charging = (CFBooleanRef)CFDictionaryGetValue(desc, CFSTR(kIOPSIsChargingKey));
    CFStringRef state_str = (CFStringRef)CFDictionaryGetValue(desc, CFSTR(kIOPSPowerSourceStateKey));

    int cur_i = 0, max_i = 0;
    if (!cur || !max) continue;
    if (!CFNumberGetValue(cur, kCFNumberIntType, &cur_i) ||
        !CFNumberGetValue(max, kCFNumberIntType, &max_i) || max_i <= 0)
      continue;

    st->last_percent = (double)cur_i * 100.0 / (double)max_i;
    st->last_is_charging = (charging && CFBooleanGetValue(charging)) ? 1 : 0;
    if (state_str && CFGetTypeID(state_str) == CFStringGetTypeID()) {
      char buf[32] = "";
      if (CFStringGetCString(state_str, buf, (CFIndex)sizeof(buf), kCFStringEncodingUTF8)) {
        snprintf(st->last_status, sizeof(st->last_status), "%s", buf);
      }
    }
    found = true;
    break;
  }

  CFRelease(sources);
  CFRelease(info);

  if (!found) {
    sysmon_set_error(out_error, "battery info not found");
    return SYSMON_ERR_NOT_SUPPORTED;
  }

#elif defined(__linux__)
  char cap_path[320];
  snprintf(cap_path, sizeof(cap_path), "%s/capacity", st->base_path);
  uint32_t cap = 0;
  if (!read_u32_file(cap_path, &cap)) {
    sysmon_set_error(out_error, "failed to read battery capacity");
    return SYSMON_ERR_NOT_SUPPORTED;
  }
  st->last_percent = (double)cap;

  char status_path[320];
  snprintf(status_path, sizeof(status_path), "%s/status", st->base_path);
  char status[32] = "unknown";
  if (read_string_file(status_path, status, sizeof(status))) {
    snprintf(st->last_status, sizeof(st->last_status), "%s", status);
  }
  st->last_is_charging = (strcasecmp(st->last_status, "Charging") == 0) ? 1 : 0;
#else
  (void)out_error;
  return SYSMON_ERR_NOT_SUPPORTED;
#endif

  st->has_data = true;
  }
#endif
  sysmon_result_t rc = sysmon_snapshot_builder_add_double(builder, "battery.percent", "%", st->last_percent);
  if (rc != SYSMON_OK) return rc;
  rc = sysmon_snapshot_builder_add_i64(builder, "battery.is_charging", NULL, st->last_is_charging);
  if (rc != SYSMON_OK) return rc;
  rc = sysmon_snapshot_builder_add_string(builder, "battery.status", NULL, st->last_status);
  if (rc != SYSMON_OK) return rc;
  return SYSMON_OK;
}

static void battery_destroy(void *state) { free(state); }

const sysmon_module_vtable_t *sysmon_battery_module(void) {
  static const sysmon_module_vtable_t vtable = {
      .name = "battery", .create = battery_create, .poll = battery_poll, .destroy = battery_destroy};
  return &vtable;
}
