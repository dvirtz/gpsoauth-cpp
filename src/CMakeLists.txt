set(INCLUDE_FOLDER ${CMAKE_SOURCE_DIR}/include/gpsoauth)
set(SOURCES GPSOAuthClient.cpp GoogleKeyUtils.cpp)
set(HEADERS ${INCLUDE_FOLDER}/GPSOAuthClient.h ${INCLUDE_FOLDER}/GoogleKeyUtils.h ${INCLUDE_FOLDER}/StringMap.h)

add_library(GPSOAuthClient ${HEADERS} ${SOURCES})

target_include_directories(GPSOAuthClient PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>)

target_link_libraries(GPSOAuthClient cpr::cpr cryptopp-static)

install(
    TARGETS GPSOAuthClient
    EXPORT "${targets_export_name}"
    LIBRARY DESTINATION "lib"
    ARCHIVE DESTINATION "lib"
    RUNTIME DESTINATION "bin"
    INCLUDES DESTINATION "${include_install_dir}"
)