cmake_minimum_required(VERSION 3.5)

set(TARGET_NAME data360)
set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)
project(${TARGET_NAME})
enable_testing()
set(CMAKE_CXX_STANDARD "17" CACHE STRING "C++ standard to enforce")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(src/include)
set(EXTENSION_SOURCES
    src/data360_extension.cpp
    src/native_runtime.cpp
    src/query_api.cpp
    src/scan_runtime.cpp
    src/type_mapping.cpp)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})
target_compile_features(${EXTENSION_NAME} PUBLIC cxx_std_17)
target_compile_features(${LOADABLE_EXTENSION_NAME} PUBLIC cxx_std_17)

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
