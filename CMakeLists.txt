cmake_minimum_required(VERSION 3.5)

set(TARGET_NAME data360)
set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)
project(${TARGET_NAME})
enable_testing()
set(CMAKE_CXX_STANDARD "17" CACHE STRING "C++ standard to enforce")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(nanoarrow CONFIG REQUIRED)

# nanoarrow 0.9.0 exports its FlatCC runtime dependency as the bare
# `flatccrt` link item. The vcpkg FlatCC port suffixes the debug archive
# (`flatccrt_d`), so provide the configuration-aware target expected by
# nanoarrow's exported target.
if(NOT TARGET flatccrt)
    find_library(DATA360_FLATCCRT_RELEASE NAMES flatccrt REQUIRED)
    find_library(DATA360_FLATCCRT_DEBUG NAMES flatccrt_d flatccrt REQUIRED)
    add_library(flatccrt STATIC IMPORTED)
    set_target_properties(flatccrt PROPERTIES
        IMPORTED_CONFIGURATIONS "DEBUG;RELEASE"
        IMPORTED_LOCATION "${DATA360_FLATCCRT_RELEASE}"
        IMPORTED_LOCATION_DEBUG "${DATA360_FLATCCRT_DEBUG}"
        IMPORTED_LOCATION_RELEASE "${DATA360_FLATCCRT_RELEASE}")
endif()

include_directories(src/include)
set(EXTENSION_SOURCES
    src/arrow_ipc_chunk_reader.cpp
    src/data360_extension.cpp
    src/native_runtime.cpp
    src/query_api.cpp
    src/scan_runtime.cpp
    src/type_mapping.cpp)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})
target_compile_features(${EXTENSION_NAME} PUBLIC cxx_std_17)
target_compile_features(${LOADABLE_EXTENSION_NAME} PUBLIC cxx_std_17)
target_link_libraries(${EXTENSION_NAME} nanoarrow::nanoarrow_ipc)
target_link_libraries(${LOADABLE_EXTENSION_NAME} nanoarrow::nanoarrow_ipc)

install(TARGETS ${EXTENSION_NAME}
        EXPORT "${DUCKDB_EXPORT_SET}"
        LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
        ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")

add_executable(data360_unit_tests
    test/unit/query_api_test.cpp
    src/native_runtime.cpp
    src/query_api.cpp
    src/type_mapping.cpp)
target_include_directories(data360_unit_tests PRIVATE src/include)
target_compile_features(data360_unit_tests PRIVATE cxx_std_17)
target_compile_options(data360_unit_tests PRIVATE -Wall -Wextra -Werror)
target_link_libraries(data360_unit_tests PRIVATE duckdb)
add_test(NAME data360_unit_tests COMMAND data360_unit_tests)

add_executable(data360_scan_tests
    test/unit/data360_scan_test.cpp
    src/scan_runtime.cpp
    src/query_api.cpp)
target_include_directories(data360_scan_tests PRIVATE src/include)
target_compile_features(data360_scan_tests PRIVATE cxx_std_17)
target_compile_options(data360_scan_tests PRIVATE -Wall -Wextra -Werror -Wno-unused-parameter)
target_link_libraries(data360_scan_tests PRIVATE duckdb)
add_test(NAME data360_scan_tests COMMAND data360_scan_tests)

add_executable(data360_arrow_ipc_tests
    test/unit/arrow_ipc_chunk_reader_test.cpp
    src/arrow_ipc_chunk_reader.cpp)
target_include_directories(data360_arrow_ipc_tests PRIVATE src/include)
target_compile_features(data360_arrow_ipc_tests PRIVATE cxx_std_17)
target_compile_options(data360_arrow_ipc_tests PRIVATE -Wall -Wextra -Werror -Wno-unused-parameter)
target_compile_definitions(data360_arrow_ipc_tests PRIVATE
    DATA360_ARROW_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures")
target_link_libraries(data360_arrow_ipc_tests PRIVATE duckdb nanoarrow::nanoarrow_ipc)
add_test(NAME data360_arrow_ipc_tests COMMAND data360_arrow_ipc_tests)
