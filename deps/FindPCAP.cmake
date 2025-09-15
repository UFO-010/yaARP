 
cmake_minimum_required(VERSION 3.0)

if(NOT MODULE_NAME)
    set(MODULE_NAME FindPCAP)
endif()


unset(PCAP_INCLUDE_DIRS CACHE)
unset(PCAP_LIBRARIES CACHE)
unset(PCAP_FOUND CACHE)

if(WIN32)
    if(NOT DEFINED NPCAP_SDK_ROOT)
        set(NPCAP_SDK_ROOT "${CMAKE_CURRENT_LIST_DIR}/npcap-sdk")
    endif()

    find_path(PCAP_INCLUDE_DIRS
        NAMES pcap.h
        PATHS
            "${NPCAP_SDK_ROOT}/Include"
    )

    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(NPCAP_LIB_SUBDIR Lib)
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(NPCAP_LIB_SUBDIR Lib/x64)
    else()
        message(FATAL_ERROR "Unsupported architecture for Npcap")
    endif()

    find_library(PCAP_WPCAP_LIBRARY
        NAMES wpcap
        PATHS
            "${NPCAP_SDK_ROOT}/${NPCAP_LIB_SUBDIR}"
            "$ENV{System32}/Npcap"
    )
	
    find_library(PCAP_PACKET_LIBRARY
        NAMES Packet
        PATHS
            "${NPCAP_SDK_ROOT}/${NPCAP_LIB_SUBDIR}"
            "$ENV{System32}/Npcap"
    )

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(PCAP REQUIRED_VARS PCAP_WPCAP_LIBRARY PCAP_INCLUDE_DIRS)

    if(PCAP_FOUND)
        if(PCAP_WPCAP_LIBRARY)
            set(PCAP_LIBRARIES ${PCAP_WPCAP_LIBRARY})
        endif()
    endif()

endif()

if(UNIX)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
         pkg_check_modules(PCAP_PKG libpcap)

        if(PCAP_PKG_FOUND)
            set(PCAP_INCLUDE_DIRS ${PCAP_PKG_INCLUDE_DIRS})
            find_library(PCAP_LIBRARIES NAMES ${PCAP_PKG_LIBRARIES}
                PATHS ${PCAP_PKG_LIBRARY_DIRS}
                NO_DEFAULT_PATH
            )
        endif()
    endif()

    # Manual search
    if(NOT PCAP_LIBRARIES)
        find_path(PCAP_INCLUDE_DIRS
            pcap/pcap.h
            PATHS /usr/include /usr/local/include
        )
        find_library(PCAP_LIBRARIES
            pcap
            PATHS /usr/lib /usr/local/lib
        )
    endif()
endif()


# Проверка
if(PCAP_INCLUDE_DIRS AND PCAP_LIBRARIES)
    set(PCAP_FOUND TRUE)
else()
    set(PCAP_FOUND FALSE)
endif()

mark_as_advanced(PCAP_INCLUDE_DIRS PCAP_LIBRARIES PCAP_WPCAP_LIBRARY PCAP_PACKET_LIBRARY)

if(PCAP_FOUND)
    message(STATUS "PCAP_INCLUDE_DIRS = ${PCAP_INCLUDE_DIRS}")
    message(STATUS "PCAP_LIBRARIES = ${PCAP_LIBRARIES}")
    if(WIN32)
        message(STATUS "PCAP_PACKET_LIBRARY = ${PCAP_PACKET_LIBRARY}")
    endif()
else()
    message(FATAL_ERROR "libpcap/npсap not found")
endif()

add_library(PCAP::PCAP UNKNOWN IMPORTED)
set_target_properties(PCAP::PCAP PROPERTIES IMPORTED_LOCATION "${PCAP_LIBRARIES}" INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIRS}")

if(WIN32)
    add_library(PCAP::PACKET UNKNOWN IMPORTED)
    set_target_properties(PCAP::PACKET PROPERTIES IMPORTED_LOCATION "${PCAP_PACKET_LIBRARY}" INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIRS}")
endif()
