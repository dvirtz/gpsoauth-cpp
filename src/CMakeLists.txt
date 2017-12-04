set(INCLUDE_FOLDER ${CMAKE_SOURCE_DIR}/include/gpsoauth)
set(SOURCES GPSOAuthClient.cpp GoogleKeyUtils.cpp)
set(HEADERS ${INCLUDE_FOLDER}/GPSOAuthClient.h)

add_library(GPSOAuthClient ${HEADERS} ${SOURCES})

target_include_directories(GPSOAuthClient PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>)

target_link_libraries(GPSOAuthClient PRIVATE cpr::cpr cryptopp-static)

install(
    TARGETS GPSOAuthClient
    EXPORT "${TARGETS_EXPORT_NAME}"
    LIBRARY DESTINATION "lib"
    ARCHIVE DESTINATION "lib"
    RUNTIME DESTINATION "bin"
    INCLUDES DESTINATION "${include_install_dir}"
)