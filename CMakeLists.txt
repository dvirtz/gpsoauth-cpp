cmake_minimum_required(VERSION 3.0)

include(cmake/HunterGate.cmake)

HunterGate(
    URL "https://github.com/ruslo/hunter/archive/v0.19.161.tar.gz"
    SHA1 "9af482b6a54875bbbb221274f7290324dff29919"
)

project(gpsoauth-cpp VERSION 0.1)

set(CMAKE_CXX_STANDARD 14)

option(BUILD_TESTS "Whether to build tests" ON)

hunter_add_package(cpr)
find_package(cpr CONFIG REQUIRED)
hunter_add_package(cryptopp)
find_package(cryptopp CONFIG REQUIRED)
if(BUILD_TESTS)
hunter_add_package(Catch)
find_package(Catch CONFIG REQUIRED)
hunter_add_package(yaml-cpp)
find_package(yaml-cpp CONFIG REQUIRED)
endif()

# Installation (https://github.com/forexample/package-example) {

set(config_install_dir "lib/cmake/${PROJECT_NAME}")
set(include_install_dir "include")

set(generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")

set(version_config "${generated_dir}/${PROJECT_NAME}ConfigVersion.cmake")
set(project_config "${generated_dir}/${PROJECT_NAME}Config.cmake")
set(TARGETS_EXPORT_NAME "${PROJECT_NAME}Targets")
set(namespace "${PROJECT_NAME}::")

add_subdirectory(src)
if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()

include(CMakePackageConfigHelpers)

# Use:
#   * PROJECT_VERSION
write_basic_package_version_file(
    "${version_config}" COMPATIBILITY SameMajorVersion
)

# Use:
#   * TARGETS_EXPORT_NAME
#   * PROJECT_NAME
configure_package_config_file(
    "cmake/Config.cmake.in"
    "${project_config}"
    INSTALL_DESTINATION "${config_install_dir}"
)

install(
    DIRECTORY include/gpsoauth
    DESTINATION "${include_install_dir}"
)

install(
    FILES "${project_config}" "${version_config}"
    DESTINATION "${config_install_dir}"
)

install(
    EXPORT "${TARGETS_EXPORT_NAME}"
    NAMESPACE "${namespace}"
    DESTINATION "${config_install_dir}"
)

# }