#include "sysmon_internal.h"

#include <stdlib.h>
#include <string.h>

struct sysmon_snapshot {
  sysmon_metric_t *metrics;
  size_t count;
};

struct sysmon_snapshot_builder {
  sysmon_metric_t *metrics;
  size_t count;
  size_t capacity;
};

static sysmon_result_t ensure_capacity(sysmon_snapshot_builder_t *b, char **out_error) {
  if (b->count < b->capacity) return SYSMON_OK;
  size_t new_cap = b->capacity == 0 ? 32 : b->capacity * 2;
  void *p = realloc(b->metrics, new_cap * sizeof(*b->metrics));
  if (!p) {
    sysmon_set_error(out_error, "out of memory while growing snapshot metrics");
    return SYSMON_ERR_OUT_OF_MEMORY;
  }
  b->metrics = (sysmon_metric_t *)p;
  b->capacity = new_cap;
  return SYSMON_OK;
}

sysmon_result_t sysmon_snapshot_builder_create(sysmon_snapshot_builder_t **out_builder) {
  if (!out_builder) return SYSMON_ERR_INVALID_ARGUMENT;
  sysmon_snapshot_builder_t *b = (sysmon_snapshot_builder_t *)calloc(1, sizeof(*b));
  if (!b) return SYSMON_ERR_OUT_OF_MEMORY;
  *out_builder = b;
  return SYSMON_OK;
}

void sysmon_snapshot_builder_destroy(sysmon_snapshot_builder_t *builder) {
  if (!builder) return;
  for (size_t i = 0; i < builder->count; i++) {
    free((char *)builder->metrics[i].name);
    free((char *)builder->metrics[i].unit);
    if (builder->metrics[i].type == SYSMON_METRIC_STRING) free((char *)builder->metrics[i].value.str);
  }
  free(builder->metrics);
  free(builder);
}

sysmon_result_t sysmon_snapshot_builder_finalize(sysmon_snapshot_builder_t *builder,
                                                sysmon_snapshot_t **out_snapshot) {
  if (!builder || !out_snapshot) return SYSMON_ERR_INVALID_ARGUMENT;
  sysmon_snapshot_t *s = (sysmon_snapshot_t *)calloc(1, sizeof(*s));
  if (!s) return SYSMON_ERR_OUT_OF_MEMORY;
  s->metrics = builder->metrics;
  s->count = builder->count;
  builder->metrics = NULL;
  builder->count = 0;
  builder->capacity = 0;
  *out_snapshot = s;
  return SYSMON_OK;
}

static sysmon_result_t add_common(sysmon_snapshot_builder_t *b, const char *name, const char *unit,
                                  sysmon_metric_type_t type, char **out_error) {
  if (!b || !name) return SYSMON_ERR_INVALID_ARGUMENT;
  sysmon_result_t rc = ensure_capacity(b, out_error);
  if (rc != SYSMON_OK) return rc;

  char *name_copy = sysmon_strdup(name);
  char *unit_copy = unit ? sysmon_strdup(unit) : NULL;
  if (!name_copy || (unit && !unit_copy)) {
    free(name_copy);
    free(unit_copy);
    sysmon_set_error(out_error, "out of memory while duplicating metric strings");
    return SYSMON_ERR_OUT_OF_MEMORY;
  }

  sysmon_metric_t *m = &b->metrics[b->count++];
  memset(m, 0, sizeof(*m));
  m->type = type;
  m->name = name_copy;
  m->unit = unit_copy;
  return SYSMON_OK;
}

sysmon_result_t sysmon_snapshot_builder_add_double(sysmon_snapshot_builder_t *builder,
                                                   const char *name, const char *unit,
                                                   double value) {
  char *err = NULL;
  sysmon_result_t rc = add_common(builder, name, unit, SYSMON_METRIC_DOUBLE, &err);
  free(err);
  if (rc != SYSMON_OK) return rc;
  builder->metrics[builder->count - 1].value.f64 = value;
  return SYSMON_OK;
}

sysmon_result_t sysmon_snapshot_builder_add_i64(sysmon_snapshot_builder_t *builder,
                                                const char *name, const char *unit, int64_t value) {
  char *err = NULL;
  sysmon_result_t rc = add_common(builder, name, unit, SYSMON_METRIC_INT64, &err);
  free(err);
  if (rc != SYSMON_OK) return rc;
  builder->metrics[builder->count - 1].value.i64 = value;
  return SYSMON_OK;
}

sysmon_result_t sysmon_snapshot_builder_add_u64(sysmon_snapshot_builder_t *builder,
                                                const char *name, const char *unit,
                                                uint64_t value) {
  char *err = NULL;
  sysmon_result_t rc = add_common(builder, name, unit, SYSMON_METRIC_UINT64, &err);
  free(err);
  if (rc != SYSMON_OK) return rc;
  builder->metrics[builder->count - 1].value.u64 = value;
  return SYSMON_OK;
}

sysmon_result_t sysmon_snapshot_builder_add_string(sysmon_snapshot_builder_t *builder,
                                                   const char *name, const char *unit,
                                                   const char *value) {
  char *err = NULL;
  sysmon_result_t rc = add_common(builder, name, unit, SYSMON_METRIC_STRING, &err);
  free(err);
  if (rc != SYSMON_OK) return rc;
  sysmon_metric_t *m = &builder->metrics[builder->count - 1];
  m->value.str = sysmon_strdup(value ? value : "");
  if (!m->value.str) return SYSMON_ERR_OUT_OF_MEMORY;
  return SYSMON_OK;
}

void sysmon_snapshot_destroy(sysmon_snapshot_t *snapshot) {
  if (!snapshot) return;
  for (size_t i = 0; i < snapshot->count; i++) {
    free((char *)snapshot->metrics[i].name);
    free((char *)snapshot->metrics[i].unit);
    if (snapshot->metrics[i].type == SYSMON_METRIC_STRING) free((char *)snapshot->metrics[i].value.str);
  }
  free(snapshot->metrics);
  free(snapshot);
}

size_t sysmon_snapshot_metric_count(const sysmon_snapshot_t *snapshot) {
  return snapshot ? snapshot->count : 0;
}

const sysmon_metric_t *sysmon_snapshot_metric_at(const sysmon_snapshot_t *snapshot, size_t index) {
  if (!snapshot || index >= snapshot->count) return NULL;
  return &snapshot->metrics[index];
}

const sysmon_metric_t *sysmon_snapshot_find(const sysmon_snapshot_t *snapshot, const char *name) {
  if (!snapshot || !name) return NULL;
  for (size_t i = 0; i < snapshot->count; i++) {
    if (snapshot->metrics[i].name && strcmp(snapshot->metrics[i].name, name) == 0)
      return &snapshot->metrics[i];
  }
  return NULL;
}
