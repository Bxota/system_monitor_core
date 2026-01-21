#include <sysmon/sysmon.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#endif

static void usage(const char *argv0) {
  fprintf(stderr,
          "Usage: %s [-c config.ini] [-n iterations] [--json]\n"
          "  -c <path>     Path to ini config (default: sysmon.ini)\n"
          "  -n <count>    Number of iterations (default: infinite)\n"
          "  --json        Print one JSON object per line\n",
          argv0);
}

static void print_human(const sysmon_snapshot_t *snapshot) {
  const size_t count = sysmon_snapshot_metric_count(snapshot);
  for (size_t i = 0; i < count; i++) {
    const sysmon_metric_t *m = sysmon_snapshot_metric_at(snapshot, i);
    if (!m) continue;
    printf("%s=", m->name ? m->name : "(null)");
    switch (m->type) {
      case SYSMON_METRIC_DOUBLE:
        printf("%.2f", m->value.f64);
        break;
      case SYSMON_METRIC_INT64:
        printf("%lld", (long long)m->value.i64);
        break;
      case SYSMON_METRIC_UINT64:
        printf("%llu", (unsigned long long)m->value.u64);
        break;
      case SYSMON_METRIC_STRING:
        printf("%s", m->value.str ? m->value.str : "");
        break;
    }
    if (m->unit) printf("%s", m->unit);
    if (i + 1 < count) printf("  ");
  }
  printf("\n");
}

static void json_escape(const char *s) {
  for (const unsigned char *p = (const unsigned char *)s; p && *p; p++) {
    switch (*p) {
      case '\\':
        fputs("\\\\", stdout);
        break;
      case '"':
        fputs("\\\"", stdout);
        break;
      case '\n':
        fputs("\\n", stdout);
        break;
      case '\r':
        fputs("\\r", stdout);
        break;
      case '\t':
        fputs("\\t", stdout);
        break;
      default:
        fputc(*p, stdout);
        break;
    }
  }
}

static void print_json(const sysmon_snapshot_t *snapshot) {
  const size_t count = sysmon_snapshot_metric_count(snapshot);
  fputc('{', stdout);
  for (size_t i = 0; i < count; i++) {
    const sysmon_metric_t *m = sysmon_snapshot_metric_at(snapshot, i);
    if (!m || !m->name) continue;
    if (i != 0) fputc(',', stdout);
    fputc('"', stdout);
    json_escape(m->name);
    fputc('"', stdout);
    fputc(':', stdout);
    switch (m->type) {
      case SYSMON_METRIC_DOUBLE:
        printf("%.6f", m->value.f64);
        break;
      case SYSMON_METRIC_INT64:
        printf("%lld", (long long)m->value.i64);
        break;
      case SYSMON_METRIC_UINT64:
        printf("%llu", (unsigned long long)m->value.u64);
        break;
      case SYSMON_METRIC_STRING:
        fputc('"', stdout);
        json_escape(m->value.str ? m->value.str : "");
        fputc('"', stdout);
        break;
    }
  }
  fputs("}\n", stdout);
}

static void sleep_ms(uint32_t ms) {
#if defined(_WIN32)
  Sleep(ms);
#else
  struct timespec ts;
  ts.tv_sec = (time_t)(ms / 1000u);
  ts.tv_nsec = (long)((ms % 1000u) * 1000000u);
  nanosleep(&ts, NULL);
#endif
}

int main(int argc, char **argv) {
  const char *config_path = "sysmon.ini";
  long iterations = -1;
  bool json = false;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-c") == 0) {
      if (i + 1 >= argc) {
        usage(argv[0]);
        return 2;
      }
      config_path = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "-n") == 0) {
      if (i + 1 >= argc) {
        usage(argv[0]);
        return 2;
      }
      iterations = strtol(argv[++i], NULL, 10);
      continue;
    }
    if (strcmp(argv[i], "--json") == 0) {
      json = true;
      continue;
    }
    usage(argv[0]);
    return 2;
  }

  sysmon_create_options_t options = {.ini_path = config_path};
  sysmon_t *sysmon = NULL;
  sysmon_result_t rc = sysmon_create(&options, &sysmon);
  if (rc != SYSMON_OK) {
    fprintf(stderr, "sysmon_create failed (%d)\n", (int)rc);
    return 1;
  }

  const uint32_t interval_ms = sysmon_interval_ms(sysmon);
  for (long n = 0; iterations < 0 || n < iterations; n++) {
    sysmon_snapshot_t *snapshot = NULL;
    rc = sysmon_poll(sysmon, &snapshot);
    if (rc != SYSMON_OK) {
      fprintf(stderr, "sysmon_poll failed (%d): %s\n", (int)rc,
              sysmon_last_error(sysmon) ? sysmon_last_error(sysmon) : "");
      break;
    }
    if (json) {
      print_json(snapshot);
    } else {
      print_human(snapshot);
    }
    sysmon_snapshot_destroy(snapshot);
    sleep_ms(interval_ms);
  }

  sysmon_destroy(sysmon);
  return rc == SYSMON_OK ? 0 : 1;
}
