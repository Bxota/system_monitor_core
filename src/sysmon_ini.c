#include "sysmon_internal.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef struct sysmon_ini_entry {
  char *section;
  char *key;
  char *value;
} sysmon_ini_entry_t;

struct sysmon_ini {
  sysmon_ini_entry_t *entries;
  size_t count;
  size_t capacity;
};

static char *trim(char *s) {
  while (*s && isspace((unsigned char)*s)) s++;
  size_t len = strlen(s);
  while (len > 0 && isspace((unsigned char)s[len - 1])) s[--len] = '\0';
  return s;
}

static bool starts_with_comment(const char *s) {
  return s[0] == '\0' || s[0] == ';' || s[0] == '#';
}

static sysmon_result_t push_entry(sysmon_ini_t *ini, const char *section, const char *key,
                                  const char *value, char **out_error) {
  if (ini->count == ini->capacity) {
    const size_t new_cap = ini->capacity == 0 ? 32 : ini->capacity * 2;
    void *p = realloc(ini->entries, new_cap * sizeof(*ini->entries));
    if (!p) {
      sysmon_set_error(out_error, "out of memory while growing ini entries");
      return SYSMON_ERR_OUT_OF_MEMORY;
    }
    ini->entries = (sysmon_ini_entry_t *)p;
    ini->capacity = new_cap;
  }

  sysmon_ini_entry_t *e = &ini->entries[ini->count++];
  e->section = sysmon_strdup(section ? section : "");
  e->key = sysmon_strdup(key);
  e->value = sysmon_strdup(value);
  if (!e->section || !e->key || !e->value) {
    sysmon_set_error(out_error, "out of memory while duplicating ini strings");
    return SYSMON_ERR_OUT_OF_MEMORY;
  }
  return SYSMON_OK;
}

sysmon_result_t sysmon_ini_load_file(const char *path, sysmon_ini_t **out_ini, char **out_error) {
  if (!path || !out_ini) return SYSMON_ERR_INVALID_ARGUMENT;

  FILE *f = fopen(path, "r");
  if (!f) {
    char buf[256];
    snprintf(buf, sizeof(buf), "failed to open ini file: %s (%s)", path, strerror(errno));
    sysmon_set_error(out_error, buf);
    return SYSMON_ERR_IO;
  }

  sysmon_ini_t *ini = (sysmon_ini_t *)calloc(1, sizeof(*ini));
  if (!ini) {
    fclose(f);
    sysmon_set_error(out_error, "out of memory while allocating ini");
    return SYSMON_ERR_OUT_OF_MEMORY;
  }

  char section[128] = "";
  char line[1024];
  size_t line_no = 0;
  while (fgets(line, (int)sizeof(line), f)) {
    line_no++;
    char *s = trim(line);
    if (starts_with_comment(s)) continue;

    if (s[0] == '[') {
      char *end = strchr(s, ']');
      if (!end) {
        char buf[256];
        snprintf(buf, sizeof(buf), "ini parse error at line %zu: missing ']'", line_no);
        sysmon_set_error(out_error, buf);
        sysmon_ini_destroy(ini);
        fclose(f);
        return SYSMON_ERR_PARSE;
      }
      *end = '\0';
      snprintf(section, sizeof(section), "%s", trim(s + 1));
      continue;
    }

    char *eq = strchr(s, '=');
    if (!eq) {
      char buf[256];
      snprintf(buf, sizeof(buf), "ini parse error at line %zu: expected key=value", line_no);
      sysmon_set_error(out_error, buf);
      sysmon_ini_destroy(ini);
      fclose(f);
      return SYSMON_ERR_PARSE;
    }
    *eq = '\0';
    char *key = trim(s);
    char *value = trim(eq + 1);

    sysmon_result_t rc = push_entry(ini, section, key, value, out_error);
    if (rc != SYSMON_OK) {
      sysmon_ini_destroy(ini);
      fclose(f);
      return rc;
    }
  }

  fclose(f);
  *out_ini = ini;
  return SYSMON_OK;
}

void sysmon_ini_destroy(sysmon_ini_t *ini) {
  if (!ini) return;
  for (size_t i = 0; i < ini->count; i++) {
    free(ini->entries[i].section);
    free(ini->entries[i].key);
    free(ini->entries[i].value);
  }
  free(ini->entries);
  free(ini);
}

const char *sysmon_ini_get(const sysmon_ini_t *ini, const char *section, const char *key) {
  if (!ini || !section || !key) return NULL;
  for (size_t i = 0; i < ini->count; i++) {
    const sysmon_ini_entry_t *e = &ini->entries[i];
    if (strcmp(e->section, section) == 0 && strcmp(e->key, key) == 0) return e->value;
  }
  return NULL;
}

static bool parse_bool(const char *s, bool default_value) {
  if (!s) return default_value;
  if (strcmp(s, "1") == 0) return true;
  if (strcmp(s, "0") == 0) return false;
  if (strcasecmp(s, "true") == 0) return true;
  if (strcasecmp(s, "false") == 0) return false;
  if (strcasecmp(s, "yes") == 0) return true;
  if (strcasecmp(s, "no") == 0) return false;
  if (strcasecmp(s, "on") == 0) return true;
  if (strcasecmp(s, "off") == 0) return false;
  return default_value;
}

bool sysmon_ini_get_bool(const sysmon_ini_t *ini, const char *section, const char *key,
                         bool default_value) {
  return parse_bool(sysmon_ini_get(ini, section, key), default_value);
}

uint32_t sysmon_ini_get_u32(const sysmon_ini_t *ini, const char *section, const char *key,
                            uint32_t default_value, bool *out_ok) {
  const char *v = sysmon_ini_get(ini, section, key);
  if (!v || *v == '\0') {
    if (out_ok) *out_ok = true;
    return default_value;
  }
  char *end = NULL;
  errno = 0;
  unsigned long n = strtoul(v, &end, 10);
  if (errno != 0 || end == v || (end && *end != '\0') || n > 0xfffffffful) {
    if (out_ok) *out_ok = false;
    return default_value;
  }
  if (out_ok) *out_ok = true;
  return (uint32_t)n;
}
