PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

EXT_NAME=data360
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

# The reusable distribution workflow exports BUILD_SHELL=0 but the pinned
# extension-ci-tools makefile does not forward it to CMake. Honor that input
# explicitly so extension-only builds do not compile DuckDB shell tools.
ifeq ($(BUILD_SHELL),0)
EXT_FLAGS += -DBUILD_SHELL=FALSE
endif

ifeq ($(shell uname -s),Darwin)
# DuckDB's ASan runtime deadlocks during process initialization on macOS 26.
DISABLE_SANITIZER ?= 1
DUCKDB_PLATFORM ?= osx_$(shell uname -m)
endif

include extension-ci-tools/makefiles/duckdb_extension.Makefile
