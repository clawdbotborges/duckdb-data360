PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

EXT_NAME=data360
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

ifeq ($(shell uname -s),Darwin)
# DuckDB's ASan runtime deadlocks during process initialization on macOS 26.
DISABLE_SANITIZER ?= 1
DUCKDB_PLATFORM ?= osx_$(shell uname -m)
endif

include extension-ci-tools/makefiles/duckdb_extension.Makefile
