#include "sysmon_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct sysmon {
  sysmon_config_t config;
  sysmon_ini_t *ini;
  sysmon_module_instance_t *modules;
  size_t module_count;
  char *last_error;
};

char *sysmon_strdup(const char *s) {
  if (!s) return NULL;
  size_t n = strlen(s) + 1;
  char *p = (char *)malloc(n);
  if (!p) return NULL;
  memcpy(p, s, n);
  return p;
}

void sysmon_set_error(char **target, const char *message) {
  if (!target) return;
  free(*target);
  *target = message ? sysmon_strdup(message) : NULL;
}

static sysmon_result_t init_modules(sysmon_t *sysmon) {
  size_t builtin_count = 0;
  const sysmon_module_vtable_t *builtins = sysmon_builtin_modules(&builtin_count);
  if (!builtins || builtin_count == 0) return SYSMON_ERR_INTERNAL;

  sysmon->modules = (sysmon_module_instance_t *)calloc(builtin_count, sizeof(*sysmon->modules));
  if (!sysmon->modules) return SYSMON_ERR_OUT_OF_MEMORY;
  sysmon->module_count = builtin_count;

  for (size_t i = 0; i < builtin_count; i++) {
    sysmon_module_instance_t *inst = &sysmon->modules[i];
    inst->vtable = &builtins[i];
    inst->enabled = true;
    inst->refresh_ms = 0;
    inst->last_refresh_ms = 0;

    char section[128];
    snprintf(section, sizeof(section), "module.%s", inst->vtable->name);
    inst->enabled = sysmon_ini_get_bool(sysmon->ini, section, "enabled", true);

    bool ok = true;
    inst->refresh_ms = sysmon_ini_get_u32(sysmon->ini, section, "refresh_ms", 0, &ok);
    if (!ok) {
      sysmon_set_error(&sysmon->last_error, "invalid refresh_ms (must be uint32)");
      return SYSMON_ERR_PARSE;
    }

    if (!inst->enabled) continue;

    char *err = NULL;
    sysmon_result_t rc = inst->vtable->create(sysmon->ini, section, &inst->state, &err);
    if (rc == SYSMON_ERR_NOT_SUPPORTED) {
      inst->enabled = false;
      free(err);
      continue;
    }
    if (rc != SYSMON_OK) {
      sysmon_set_error(&sysmon->last_error, err ? err : "module create failed");
      free(err);
      return rc;
    }
    free(err);
  }

  return SYSMON_OK;
}

sysmon_result_t sysmon_create(const sysmon_create_options_t *options, sysmon_t **out_sysmon) {
  if (!out_sysmon) return SYSMON_ERR_INVALID_ARGUMENT;
  *out_sysmon = NULL;

  sysmon_t *sysmon = (sysmon_t *)calloc(1, sizeof(*sysmon));
  if (!sysmon) return SYSMON_ERR_OUT_OF_MEMORY;

  const char *ini_path = options ? options->ini_path : NULL;
  if (!ini_path) ini_path = "sysmon.ini";

  char *err = NULL;
  sysmon_result_t rc = sysmon_ini_load_file(ini_path, &sysmon->ini, &err);
  if (rc != SYSMON_OK) {
    sysmon_set_error(&sysmon->last_error, err ? err : "failed to load ini");
    free(err);
    sysmon_destroy(sysmon);
    return rc;
  }
  free(err);

  rc = sysmon_config_load_from_ini(sysmon->ini, &sysmon->config, &err);
  if (rc != SYSMON_OK) {
    sysmon_set_error(&sysmon->last_error, err ? err : "failed to load config");
    free(err);
    sysmon_destroy(sysmon);
    return rc;
  }
  free(err);

  rc = init_modules(sysmon);
  if (rc != SYSMON_OK) {
    sysmon_destroy(sysmon);
    return rc;
  }

  *out_sysmon = sysmon;
  return SYSMON_OK;
}

void sysmon_destroy(sysmon_t *sysmon) {
  if (!sysmon) return;
  if (sysmon->modules) {
    for (size_t i = 0; i < sysmon->module_count; i++) {
      sysmon_module_instance_t *inst = &sysmon->modules[i];
      if (inst->state && inst->vtable && inst->vtable->destroy) inst->vtable->destroy(inst->state);
    }
  }
  free(sysmon->modules);
  sysmon_ini_destroy(sysmon->ini);
  free(sysmon->last_error);
  free(sysmon);
}

uint32_t sysmon_interval_ms(const sysmon_t *sysmon) {
  return sysmon ? sysmon->config.interval_ms : 0;
}

const char *sysmon_last_error(const sysmon_t *sysmon) { return sysmon ? sysmon->last_error : NULL; }

static void add_module_error(sysmon_snapshot_builder_t *b, const char *module_name,
                             const char *message) {
  if (!b || !module_name || !message) return;
  char name[192];
  snprintf(name, sizeof(name), "module.%s.error", module_name);
  sysmon_snapshot_builder_add_string(b, name, NULL, message);
}

sysmon_result_t sysmon_poll(sysmon_t *sysmon, sysmon_snapshot_t **out_snapshot) {
  if (!sysmon || !out_snapshot) return SYSMON_ERR_INVALID_ARGUMENT;
  *out_snapshot = NULL;

  sysmon_snapshot_builder_t *builder = NULL;
  sysmon_result_t rc = sysmon_snapshot_builder_create(&builder);
  if (rc != SYSMON_OK) return rc;

  const uint64_t now_ms = sysmon_now_ms();
  for (size_t i = 0; i < sysmon->module_count; i++) {
    sysmon_module_instance_t *inst = &sysmon->modules[i];
    if (!inst->enabled || !inst->vtable || !inst->vtable->poll) continue;

    const bool refresh_now = inst->refresh_ms == 0 || inst->last_refresh_ms == 0 ||
                             now_ms - inst->last_refresh_ms >= inst->refresh_ms;

    char *module_err = NULL;
    sysmon_result_t mrc = inst->vtable->poll(inst->state, now_ms, refresh_now, builder, &module_err);
    if (mrc == SYSMON_OK) {
      if (refresh_now) inst->last_refresh_ms = now_ms;
      free(module_err);
      continue;
    }
    if (mrc == SYSMON_ERR_OUT_OF_MEMORY) {
      sysmon_set_error(&sysmon->last_error, module_err ? module_err : "out of memory");
      free(module_err);
      sysmon_snapshot_builder_destroy(builder);
      return SYSMON_ERR_OUT_OF_MEMORY;
    }

    add_module_error(builder, inst->vtable->name, module_err ? module_err : "module error");
    free(module_err);
  }

  rc = sysmon_snapshot_builder_finalize(builder, out_snapshot);
  sysmon_snapshot_builder_destroy(builder);
  return rc;
}
