#pragma once

#include <sysmon/sysmon.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct sysmon_ini sysmon_ini_t;

typedef struct sysmon_snapshot_builder sysmon_snapshot_builder_t;

typedef struct sysmon_module_vtable {
  const char *name;
  sysmon_result_t (*create)(const sysmon_ini_t *ini, const char *section, void **out_state,
                            char **out_error);
  sysmon_result_t (*poll)(void *state, uint64_t now_ms, bool refresh_now,
                          sysmon_snapshot_builder_t *builder, char **out_error);
  void (*destroy)(void *state);
} sysmon_module_vtable_t;

typedef struct sysmon_module_instance {
  const sysmon_module_vtable_t *vtable;
  void *state;
  bool enabled;
  uint32_t refresh_ms;
  uint64_t last_refresh_ms;
} sysmon_module_instance_t;

typedef struct sysmon_config {
  uint32_t interval_ms;
} sysmon_config_t;

sysmon_result_t sysmon_config_load_from_ini(const sysmon_ini_t *ini, sysmon_config_t *out_config,
                                           char **out_error);

sysmon_result_t sysmon_ini_load_file(const char *path, sysmon_ini_t **out_ini, char **out_error);
void sysmon_ini_destroy(sysmon_ini_t *ini);

const char *sysmon_ini_get(const sysmon_ini_t *ini, const char *section, const char *key);
bool sysmon_ini_get_bool(const sysmon_ini_t *ini, const char *section, const char *key,
                         bool default_value);
uint32_t sysmon_ini_get_u32(const sysmon_ini_t *ini, const char *section, const char *key,
                            uint32_t default_value, bool *out_ok);

sysmon_result_t sysmon_snapshot_builder_create(sysmon_snapshot_builder_t **out_builder);
sysmon_result_t sysmon_snapshot_builder_finalize(sysmon_snapshot_builder_t *builder,
                                                sysmon_snapshot_t **out_snapshot);
void sysmon_snapshot_builder_destroy(sysmon_snapshot_builder_t *builder);

sysmon_result_t sysmon_snapshot_builder_add_double(sysmon_snapshot_builder_t *builder,
                                                   const char *name, const char *unit,
                                                   double value);
sysmon_result_t sysmon_snapshot_builder_add_i64(sysmon_snapshot_builder_t *builder,
                                                const char *name, const char *unit,
                                                int64_t value);
sysmon_result_t sysmon_snapshot_builder_add_u64(sysmon_snapshot_builder_t *builder,
                                                const char *name, const char *unit,
                                                uint64_t value);
sysmon_result_t sysmon_snapshot_builder_add_string(sysmon_snapshot_builder_t *builder,
                                                   const char *name, const char *unit,
                                                   const char *value);

uint64_t sysmon_now_ms(void);

const sysmon_module_vtable_t *sysmon_builtin_modules(size_t *out_count);

char *sysmon_strdup(const char *s);
void sysmon_set_error(char **target, const char *message);
