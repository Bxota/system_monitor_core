cmake_minimum_required(VERSION 3.20)

project(sysmon C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(SYSMON_BUILD_CLI "Build sysmon CLI tool" ON)

add_library(sysmon
  src/sysmon.c
  src/sysmon_config.c
  src/sysmon_ini.c
  src/sysmon_snapshot.c
  src/sysmon_time.c
  src/modules/builtin.c
  src/modules/cpu.c
  src/modules/ram.c
  src/modules/battery.c
  src/modules/network.c
  src/modules/storage.c
)

target_include_directories(sysmon
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(APPLE)
  target_link_libraries(sysmon PRIVATE "-framework CoreFoundation" "-framework IOKit")
endif()

if(SYSMON_BUILD_CLI)
  add_executable(sysmon-cli tools/sysmon-cli.c)
  target_link_libraries(sysmon-cli PRIVATE sysmon)
endif()
