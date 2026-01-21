#include "../sysmon_internal.h"

const sysmon_module_vtable_t *sysmon_cpu_module(void);
const sysmon_module_vtable_t *sysmon_ram_module(void);
const sysmon_module_vtable_t *sysmon_battery_module(void);
const sysmon_module_vtable_t *sysmon_network_module(void);

const sysmon_module_vtable_t *sysmon_builtin_modules(size_t *out_count) {
  static sysmon_module_vtable_t modules[4];
  static bool initialized = false;
  if (!initialized) {
    modules[0] = *sysmon_cpu_module();
    modules[1] = *sysmon_ram_module();
    modules[2] = *sysmon_battery_module();
    modules[3] = *sysmon_network_module();
    initialized = true;
  }
  if (out_count) *out_count = 4;
  return modules;
}
