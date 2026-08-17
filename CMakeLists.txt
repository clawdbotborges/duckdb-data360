cmake_minimum_required(VERSION 3.5)

set(TARGET_NAME data360)
set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)
project(${TARGET_NAME})
enable_testing()
set(CMAKE_CXX_STANDARD "17" CACHE STRING "C++ standard to enforce")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(nanoarrow CONFIG REQUIRED)
find_package(CURL CONFIG REQUIRED)
find_package(Threads REQUIRED)

set(DATA360_PLATFORM_LIBS duckdb_mbedtls duckdb_yyjson Threads::Threads)
if(APPLE)
    find_library(DATA360_SECURITY_FRAMEWORK Security REQUIRED)
    list(APPEND DATA360_PLATFORM_LIBS ${DATA360_SECURITY_FRAMEWORK})
elseif(WIN32)
    list(APPEND DATA360_PLATFORM_LIBS bcrypt ws2_32)
endif()

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
    src/auth_functions.cpp
    src/data360_extension.cpp
    src/auth_session_registry.cpp
    src/error_codes.cpp
    src/libcurl_transport.cpp
    src/loopback_listener.cpp
    src/native_runtime.cpp
    src/oauth_pkce.cpp
    src/query_api.cpp
    src/salesforce_oauth_provider.cpp
    src/scan_runtime.cpp
    src/session_credentials.cpp
    src/type_mapping.cpp)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})
target_compile_features(${EXTENSION_NAME} PUBLIC cxx_std_17)
target_compile_features(${LOADABLE_EXTENSION_NAME} PUBLIC cxx_std_17)
target_link_libraries(${EXTENSION_NAME} nanoarrow::nanoarrow_ipc CURL::libcurl ${DATA360_PLATFORM_LIBS})
target_link_libraries(${LOADABLE_EXTENSION_NAME} nanoarrow::nanoarrow_ipc CURL::libcurl ${DATA360_PLATFORM_LIBS})

if(MSVC)
    # DuckDB v1.5.5 headers trigger these diagnostics under MSVC /W4;
    # keep /WX for project code while matching the narrow inherited-header
    # suppression used by the GCC/Clang path.
    set(DATA360_STRICT_WARNING_FLAGS /W4 /WX /wd4100 /wd4146 /wd4458)
else()
    set(DATA360_STRICT_WARNING_FLAGS -Wall -Wextra -Werror -Wno-unused-parameter)
endif()

install(TARGETS ${EXTENSION_NAME}
        EXPORT "${DUCKDB_EXPORT_SET}"
        LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
        ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")

add_executable(data360_unit_tests
    test/unit/query_api_test.cpp
    src/libcurl_transport.cpp
    src/native_runtime.cpp
    src/query_api.cpp
    src/type_mapping.cpp)
target_include_directories(data360_unit_tests PRIVATE src/include)
target_compile_features(data360_unit_tests PRIVATE cxx_std_17)
target_compile_options(data360_unit_tests PRIVATE ${DATA360_STRICT_WARNING_FLAGS})
target_link_libraries(data360_unit_tests PRIVATE duckdb_static dummy_static_extension_loader CURL::libcurl)
add_test(NAME data360_unit_tests COMMAND data360_unit_tests)

add_executable(data360_scan_tests
    test/unit/data360_scan_test.cpp
    src/scan_runtime.cpp
    src/query_api.cpp)
target_include_directories(data360_scan_tests PRIVATE src/include)
target_compile_features(data360_scan_tests PRIVATE cxx_std_17)
target_compile_options(data360_scan_tests PRIVATE ${DATA360_STRICT_WARNING_FLAGS})
target_link_libraries(data360_scan_tests PRIVATE duckdb_static dummy_static_extension_loader)
add_test(NAME data360_scan_tests COMMAND data360_scan_tests)

add_executable(data360_arrow_ipc_tests
    test/unit/arrow_ipc_chunk_reader_test.cpp
    src/arrow_ipc_chunk_reader.cpp)
target_include_directories(data360_arrow_ipc_tests PRIVATE src/include)
target_compile_features(data360_arrow_ipc_tests PRIVATE cxx_std_17)
target_compile_options(data360_arrow_ipc_tests PRIVATE ${DATA360_STRICT_WARNING_FLAGS})
target_compile_definitions(data360_arrow_ipc_tests PRIVATE
    DATA360_ARROW_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures")
target_link_libraries(data360_arrow_ipc_tests PRIVATE duckdb_static dummy_static_extension_loader nanoarrow::nanoarrow_ipc)
add_test(NAME data360_arrow_ipc_tests COMMAND data360_arrow_ipc_tests)

add_executable(data360_auth_core_tests
    test/unit/oauth_pkce_test.cpp
    src/oauth_pkce.cpp)
target_include_directories(data360_auth_core_tests PRIVATE src/include)
target_compile_features(data360_auth_core_tests PRIVATE cxx_std_17)
target_compile_options(data360_auth_core_tests PRIVATE ${DATA360_STRICT_WARNING_FLAGS})
target_link_libraries(data360_auth_core_tests PRIVATE ${DATA360_PLATFORM_LIBS})
add_test(NAME data360_auth_core_tests COMMAND data360_auth_core_tests)

add_executable(data360_loopback_listener_tests
    test/unit/loopback_listener_test.cpp
    src/loopback_listener.cpp
    src/oauth_pkce.cpp)
target_include_directories(data360_loopback_listener_tests PRIVATE src/include)
target_compile_features(data360_loopback_listener_tests PRIVATE cxx_std_17)
target_compile_options(data360_loopback_listener_tests PRIVATE ${DATA360_STRICT_WARNING_FLAGS})
target_link_libraries(data360_loopback_listener_tests PRIVATE ${DATA360_PLATFORM_LIBS})
add_test(NAME data360_loopback_listener_tests COMMAND data360_loopback_listener_tests)

add_executable(data360_auth_session_registry_tests
    test/unit/auth_session_registry_test.cpp
    src/auth_session_registry.cpp
    src/error_codes.cpp
    src/oauth_pkce.cpp)
target_include_directories(data360_auth_session_registry_tests PRIVATE src/include)
target_compile_features(data360_auth_session_registry_tests PRIVATE cxx_std_17)
target_compile_options(data360_auth_session_registry_tests PRIVATE ${DATA360_STRICT_WARNING_FLAGS})
target_link_libraries(data360_auth_session_registry_tests PRIVATE duckdb_static dummy_static_extension_loader ${DATA360_PLATFORM_LIBS})
add_test(NAME data360_auth_session_registry_tests COMMAND data360_auth_session_registry_tests)

add_executable(data360_error_codes_tests
    test/unit/error_codes_test.cpp
    src/error_codes.cpp)
target_include_directories(data360_error_codes_tests PRIVATE src/include)
target_compile_features(data360_error_codes_tests PRIVATE cxx_std_17)
target_compile_options(data360_error_codes_tests PRIVATE ${DATA360_STRICT_WARNING_FLAGS})
add_test(NAME data360_error_codes_tests COMMAND data360_error_codes_tests)

add_executable(data360_salesforce_oauth_provider_tests
    test/unit/salesforce_oauth_provider_test.cpp
    src/salesforce_oauth_provider.cpp
    src/auth_session_registry.cpp
    src/error_codes.cpp
    src/oauth_pkce.cpp)
target_include_directories(data360_salesforce_oauth_provider_tests PRIVATE src/include)
target_compile_features(data360_salesforce_oauth_provider_tests PRIVATE cxx_std_17)
target_compile_options(data360_salesforce_oauth_provider_tests PRIVATE ${DATA360_STRICT_WARNING_FLAGS})
target_link_libraries(data360_salesforce_oauth_provider_tests PRIVATE duckdb_static dummy_static_extension_loader ${DATA360_PLATFORM_LIBS})
add_test(NAME data360_salesforce_oauth_provider_tests COMMAND data360_salesforce_oauth_provider_tests)

add_executable(data360_session_credentials_tests
    test/unit/session_credentials_test.cpp
    src/session_credentials.cpp
    src/auth_session_registry.cpp
    src/error_codes.cpp
    src/oauth_pkce.cpp)
target_include_directories(data360_session_credentials_tests PRIVATE src/include)
target_compile_features(data360_session_credentials_tests PRIVATE cxx_std_17)
target_compile_options(data360_session_credentials_tests PRIVATE ${DATA360_STRICT_WARNING_FLAGS})
target_link_libraries(data360_session_credentials_tests PRIVATE duckdb_static ${DATA360_PLATFORM_LIBS})
link_extension_libraries(data360_session_credentials_tests PRIVATE)
add_test(NAME data360_session_credentials_tests COMMAND data360_session_credentials_tests)

add_executable(data360_auth_functions_tests
    test/unit/auth_functions_test.cpp
    src/auth_functions.cpp
    src/auth_session_registry.cpp
    src/error_codes.cpp
    src/libcurl_transport.cpp
    src/loopback_listener.cpp
    src/oauth_pkce.cpp
    src/salesforce_oauth_provider.cpp
    src/session_credentials.cpp)
target_include_directories(data360_auth_functions_tests PRIVATE src/include)
target_compile_features(data360_auth_functions_tests PRIVATE cxx_std_17)
target_compile_options(data360_auth_functions_tests PRIVATE ${DATA360_STRICT_WARNING_FLAGS})
target_link_libraries(data360_auth_functions_tests PRIVATE duckdb_static dummy_static_extension_loader CURL::libcurl ${DATA360_PLATFORM_LIBS})
add_test(NAME data360_auth_functions_tests COMMAND data360_auth_functions_tests)
