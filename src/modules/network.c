#include "../sysmon_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#endif

#define SYSMON_IFNAME_LEN 64

typedef struct network_state {
  char ifname[SYSMON_IFNAME_LEN];
  bool include_loopback;
  uint64_t last_rx_bytes;
  uint64_t last_tx_bytes;
  uint64_t last_ts_ms;
  double last_rx_rate;
  double last_tx_rate;
  bool has_data;
} network_state_t;

static void copy_ifname(char *dst, size_t dst_len, const char *src) {
  if (!dst || dst_len == 0) return;
  if (!src) {
    dst[0] = '\0';
    return;
  }
  snprintf(dst, dst_len, "%s", src);
}

static bool read_interface_bytes(const char *requested, bool include_loopback, uint64_t *out_rx,
                                 uint64_t *out_tx, char *out_selected, size_t out_selected_len,
                                 char **out_error) {
  if (!out_rx || !out_tx) return false;
  const bool has_request = requested && *requested;

#if defined(__APPLE__)
  struct ifaddrs *ifap = NULL;
  if (getifaddrs(&ifap) != 0) {
    sysmon_set_error(out_error, "getifaddrs failed");
    return false;
  }

  bool found = false;
  for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
    if (!ifa->ifa_name || !ifa->ifa_addr) continue;
    if (ifa->ifa_addr->sa_family != AF_LINK) continue;
    if (!(ifa->ifa_flags & IFF_UP)) continue;
    if (has_request && strcmp(ifa->ifa_name, requested) != 0) continue;
    if (!include_loopback && !has_request && (ifa->ifa_flags & IFF_LOOPBACK)) continue;
    struct if_data *data = (struct if_data *)ifa->ifa_data;
    if (!data) continue;
    *out_rx = (uint64_t)data->ifi_ibytes;
    *out_tx = (uint64_t)data->ifi_obytes;
    copy_ifname(out_selected, out_selected_len, ifa->ifa_name);
    found = true;
    break;
  }

  freeifaddrs(ifap);
  if (!found) {
    sysmon_set_error(out_error, has_request ? "requested interface not found" : "no interface found");
  }
  return found;

#elif defined(__linux__)
  FILE *f = fopen("/proc/net/dev", "r");
  if (!f) {
    sysmon_set_error(out_error, "failed to open /proc/net/dev");
    return false;
  }
  char line[512];
  int line_no = 0;
  bool found = false;
  while (fgets(line, (int)sizeof(line), f)) {
    line_no++;
    if (line_no <= 2) continue;
    char ifname[SYSMON_IFNAME_LEN] = "";
    unsigned long long rx = 0, tx = 0;
    int scanned = sscanf(line, " %63[^:]: %llu %*u %*u %*u %*u %*u %*u %*u %llu", ifname, &rx, &tx);
    if (scanned != 3) continue;
    if (has_request && strcmp(ifname, requested) != 0) continue;
    if (!include_loopback && !has_request && strcmp(ifname, "lo") == 0) continue;
    *out_rx = (uint64_t)rx;
    *out_tx = (uint64_t)tx;
    copy_ifname(out_selected, out_selected_len, ifname);
    found = true;
    break;
  }
  fclose(f);

  if (!found) {
    sysmon_set_error(out_error, has_request ? "requested interface not found" : "no interface found");
  }
  return found;
#else
  (void)requested;
  (void)include_loopback;
  (void)out_selected;
  (void)out_selected_len;
  sysmon_set_error(out_error, "network module not supported on this platform");
  return false;
#endif
}

static sysmon_result_t network_create(const sysmon_ini_t *ini, const char *section,
                                      void **out_state, char **out_error) {
  if (!out_state) return SYSMON_ERR_INVALID_ARGUMENT;
  network_state_t *st = (network_state_t *)calloc(1, sizeof(*st));
  if (!st) return SYSMON_ERR_OUT_OF_MEMORY;

  st->include_loopback = sysmon_ini_get_bool(ini, section, "include_loopback", false);

  const char *iface = sysmon_ini_get(ini, section, "interface");
  if (iface && *iface) {
    copy_ifname(st->ifname, sizeof(st->ifname), iface);
  } else {
    st->ifname[0] = '\0';
  }

  char *err = NULL;
  uint64_t rx = 0, tx = 0;
  char selected[SYSMON_IFNAME_LEN] = "";
  if (!read_interface_bytes(st->ifname[0] ? st->ifname : NULL, st->include_loopback, &rx, &tx,
                            selected, sizeof(selected), &err)) {
    sysmon_set_error(out_error, err ? err : "network interface not available");
    free(err);
    free(st);
    return SYSMON_ERR_NOT_SUPPORTED;
  }
  free(err);

  if (!st->ifname[0]) copy_ifname(st->ifname, sizeof(st->ifname), selected);

  st->last_rx_bytes = 0;
  st->last_tx_bytes = 0;
  st->last_ts_ms = 0;
  st->last_rx_rate = 0.0;
  st->last_tx_rate = 0.0;
  st->has_data = false;

  *out_state = st;
  return SYSMON_OK;
}

static sysmon_result_t network_poll(void *state, uint64_t now_ms, bool refresh_now,
                                    sysmon_snapshot_builder_t *builder, char **out_error) {
  network_state_t *st = (network_state_t *)state;
  if (!st || !builder) return SYSMON_ERR_INVALID_ARGUMENT;

  if (refresh_now || !st->has_data) {
    uint64_t rx = 0, tx = 0;
    char *err = NULL;
    if (!read_interface_bytes(st->ifname, st->include_loopback, &rx, &tx, NULL, 0, &err)) {
      sysmon_set_error(out_error, err ? err : "failed to read network counters");
      free(err);
      return SYSMON_ERR_IO;
    }
    free(err);

    if (st->has_data && st->last_ts_ms > 0 && now_ms > st->last_ts_ms) {
      const double seconds = (double)(now_ms - st->last_ts_ms) / 1000.0;
      const uint64_t rx_delta = rx >= st->last_rx_bytes ? (rx - st->last_rx_bytes) : 0;
      const uint64_t tx_delta = tx >= st->last_tx_bytes ? (tx - st->last_tx_bytes) : 0;
      st->last_rx_rate = seconds > 0.0 ? (double)rx_delta / seconds : 0.0;
      st->last_tx_rate = seconds > 0.0 ? (double)tx_delta / seconds : 0.0;
    } else {
      st->last_rx_rate = 0.0;
      st->last_tx_rate = 0.0;
    }

    st->last_rx_bytes = rx;
    st->last_tx_bytes = tx;
    st->last_ts_ms = now_ms;
    st->has_data = true;
  }

  sysmon_result_t rc = sysmon_snapshot_builder_add_string(builder, "network.interface", NULL, st->ifname);
  if (rc != SYSMON_OK) return rc;
  rc = sysmon_snapshot_builder_add_u64(builder, "network.rx_bytes", "B", st->last_rx_bytes);
  if (rc != SYSMON_OK) return rc;
  rc = sysmon_snapshot_builder_add_u64(builder, "network.tx_bytes", "B", st->last_tx_bytes);
  if (rc != SYSMON_OK) return rc;
  rc = sysmon_snapshot_builder_add_double(builder, "network.rx_bytes_per_sec", "B/s", st->last_rx_rate);
  if (rc != SYSMON_OK) return rc;
  rc = sysmon_snapshot_builder_add_double(builder, "network.tx_bytes_per_sec", "B/s", st->last_tx_rate);
  if (rc != SYSMON_OK) return rc;
  return SYSMON_OK;
}

static void network_destroy(void *state) { free(state); }

const sysmon_module_vtable_t *sysmon_network_module(void) {
  static const sysmon_module_vtable_t vtable = {
      .name = "network", .create = network_create, .poll = network_poll, .destroy = network_destroy};
  return &vtable;
}
