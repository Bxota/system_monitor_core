#include "sysmon_internal.h"

#include <stdio.h>

sysmon_result_t sysmon_config_load_from_ini(const sysmon_ini_t *ini, sysmon_config_t *out_config,
                                           char **out_error) {
  if (!out_config) return SYSMON_ERR_INVALID_ARGUMENT;

  out_config->interval_ms = 1000;
  if (!ini) return SYSMON_OK;

  bool ok = true;
  uint32_t interval_ms = sysmon_ini_get_u32(ini, "sysmon", "interval_ms", out_config->interval_ms,
                                           &ok);
  if (!ok || interval_ms == 0) {
    sysmon_set_error(out_error, "invalid sysmon.interval_ms (must be an integer > 0)");
    return SYSMON_ERR_PARSE;
  }
  out_config->interval_ms = interval_ms;
  return SYSMON_OK;
}

