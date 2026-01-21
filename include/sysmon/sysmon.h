#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sysmon sysmon_t;
typedef struct sysmon_snapshot sysmon_snapshot_t;

typedef enum sysmon_result {
  SYSMON_OK = 0,
  SYSMON_ERR_INVALID_ARGUMENT = 1,
  SYSMON_ERR_IO = 2,
  SYSMON_ERR_PARSE = 3,
  SYSMON_ERR_NOT_SUPPORTED = 4,
  SYSMON_ERR_OUT_OF_MEMORY = 5,
  SYSMON_ERR_INTERNAL = 6,
} sysmon_result_t;

typedef enum sysmon_metric_type {
  SYSMON_METRIC_DOUBLE = 0,
  SYSMON_METRIC_INT64 = 1,
  SYSMON_METRIC_UINT64 = 2,
  SYSMON_METRIC_STRING = 3,
} sysmon_metric_type_t;

typedef struct sysmon_metric {
  const char *name;
  const char *unit;
  sysmon_metric_type_t type;
  union {
    double f64;
    int64_t i64;
    uint64_t u64;
    const char *str;
  } value;
} sysmon_metric_t;

typedef struct sysmon_create_options {
  const char *ini_path;
} sysmon_create_options_t;

sysmon_result_t sysmon_create(const sysmon_create_options_t *options, sysmon_t **out_sysmon);
void sysmon_destroy(sysmon_t *sysmon);

sysmon_result_t sysmon_poll(sysmon_t *sysmon, sysmon_snapshot_t **out_snapshot);
void sysmon_snapshot_destroy(sysmon_snapshot_t *snapshot);

size_t sysmon_snapshot_metric_count(const sysmon_snapshot_t *snapshot);
const sysmon_metric_t *sysmon_snapshot_metric_at(const sysmon_snapshot_t *snapshot, size_t index);
const sysmon_metric_t *sysmon_snapshot_find(const sysmon_snapshot_t *snapshot, const char *name);

uint32_t sysmon_interval_ms(const sysmon_t *sysmon);
const char *sysmon_last_error(const sysmon_t *sysmon);

#ifdef __cplusplus
}
#endif

