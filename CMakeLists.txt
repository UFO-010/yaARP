cmake_minimum_required(VERSION 3.5)

project(yaARP LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/deps/")

find_package(PCAP REQUIRED)

find_package(Libnet REQUIRED)


set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(${PROJECT_NAME}_compiler_flags INTERFACE)
add_library(${PROJECT_NAME}_compiler_flags_c INTERFACE)



set(SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/src/adapter_info.c"
    "${CMAKE_CURRENT_LIST_DIR}/src/resolve_win_names.c"
    "${CMAKE_CURRENT_LIST_DIR}/src/packet_processor.c"
    "${CMAKE_CURRENT_LIST_DIR}/src/tcp_proxy.c"
    "${CMAKE_CURRENT_LIST_DIR}/src/arp_module.c"
)

set(HEADERS
    "${CMAKE_CURRENT_LIST_DIR}/include/adapter_info.h"
    "${CMAKE_CURRENT_LIST_DIR}/include/resolve_win_names.h"
    "${CMAKE_CURRENT_LIST_DIR}/include/packet_processor.h"
    "${CMAKE_CURRENT_LIST_DIR}/include/tcp_proxy.h"
    "${CMAKE_CURRENT_LIST_DIR}/include/arp_module.h"
)

add_library(${PROJECT_NAME} STATIC ${SOURCES} ${HEADERS})

target_include_directories(${PROJECT_NAME} PUBLIC
    "${CMAKE_CURRENT_LIST_DIR}/src/"
    "${CMAKE_CURRENT_LIST_DIR}/include/"
)

target_link_libraries(${PROJECT_NAME}_compiler_flags INTERFACE ${PROJECT_NAME}_compiler_flags_c)
target_compile_features(${PROJECT_NAME}_compiler_flags INTERFACE c_std_11)


if(WIN32)
    target_link_libraries(${PROJECT_NAME} PUBLIC wsock32 ws2_32 Iphlpapi)
endif()

target_link_libraries(${PROJECT_NAME} PUBLIC PCAP::PCAP)
target_include_directories(${PROJECT_NAME} PUBLIC ${PCAP_INCLUDE_DIRS})

target_link_libraries(${PROJECT_NAME} PUBLIC Libnet::LIBNET)
target_include_directories(${PROJECT_NAME} PUBLIC ${LIBNET_INCLUDE_DIRS})

if(WIN32)
    target_link_libraries(Libnet::LIBNET INTERFACE PCAP::PACKET)
endif()

if(UNIX)
    file(COPY "${CMAKE_CURRENT_LIST_DIR}/setup_network_user.sh" DESTINATION "${CMAKE_BINARY_DIR}")
endif()

if(WIN32)
    get_target_property(TARGET_OUTPUT_DIR ${PROJECT_NAME} RUNTIME_OUTPUT_DIRECTORY)
    if(NOT TARGET_OUTPUT_DIR)
        set(TARGET_OUTPUT_DIR ${CMAKE_BINARY_DIR})
    endif()


    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${PCAP_LIBRARIES}
            ${PCAP_PACKET_LIBRARY}
            ${LIBNET_LIBRARIES}
            ${TARGET_OUTPUT_DIR}
    )
endif()
