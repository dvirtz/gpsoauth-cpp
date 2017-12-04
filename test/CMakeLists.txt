add_executable(tests TestsMain.cpp Tests.cpp config.h.in)

set(CONFIG_YAML_PATH ${CMAKE_CURRENT_SOURCE_DIR}/config.yaml CACHE PATH "Path of config.yaml")

configure_file(config.h.in config.h @ONLY)

target_include_directories(tests PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(tests PRIVATE GPSOAuthClient Catch::Catch yaml-cpp::yaml-cpp)

add_test(tests tests)