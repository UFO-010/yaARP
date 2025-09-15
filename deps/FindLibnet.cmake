
cmake_minimum_required(VERSION 3.0)

if(NOT MODULE_NAME)
    set(MODULE_NAME FindLibnet)
endif()

unset(LIBNET_INCLUDE_DIRS CACHE)
unset(LIBNET_LIBRARIES CACHE)
unset(LIBNET_FOUND CACHE)


if(WIN32)
    if(NOT DEFINED LIBNET_PATH_ROOT)
        set(LIBNET_PATH_ROOT "${CMAKE_CURRENT_LIST_DIR}/libnet")
    endif()

    find_path(LIBNET_INCLUDE_DIRS
        NAMES libnet.h
        PATHS
            "${LIBNET_PATH_ROOT}/include"
    )

    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(LIBNET_LIB_SUBDIR lib/x86)
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(LIBNET_LIB_SUBDIR lib/x64)
    else()
        message(FATAL_ERROR "Unsupported architecture for Libnet")
    endif()

    find_library(LIBNET_LIBRARY
        NAMES libnet
        PATHS "${LIBNET_PATH_ROOT}/${LIBNET_LIB_SUBDIR}"
    )

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(Libnet REQUIRED_VARS LIBNET_LIBRARY LIBNET_INCLUDE_DIRS)

    set(LIBNET_FOUND ${Libnet_FOUND})
    if(LIBNET_FOUND)
        if(LIBNET_LIBRARY)
            set(LIBNET_LIBRARIES ${LIBNET_LIBRARY})
        endif()
    endif()

endif()

if(UNIX)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
		pkg_check_modules(LIBNET_PKG libnet)
        if(LIBNET_PKG_FOUND)
            set(LIBNET_INCLUDE_DIRS ${LIBNET_PKG_INCLUDE_DIRS})
            find_library(LIBNET_LIBRARIES NAMES ${LIBNET_PKG_LIBRARIES}
                PATHS ${LIBNET_PKG_LIBRARY_DIRS}
                NO_DEFAULT_PATH
            )
        endif()
    endif()

    # Manual search
    if(NOT LIBNET_LIBRARIES)
        find_path(LIBNET_INCLUDE_DIRS
			libnet/libnet.h
			PATHS /usr/include /usr/local/include
        )
        find_library(LIBNET_LIBRARIES
            libnet
			PATHS /usr/lib /usr/local/lib
        )
    endif()
endif()

if(LIBNET_INCLUDE_DIRS AND LIBNET_LIBRARIES)
	set(LIBNET_FOUND TRUE)
else()
	set(LIBNET_FOUND FALSE)
endif()

if(LIBNET_FOUND)
    message(STATUS "LIBNET_INCLUDE_DIRS = ${LIBNET_INCLUDE_DIRS}")
    message(STATUS "LIBNET_LIBRARIES = ${LIBNET_LIBRARIES}")
else()
    message(FATAL_ERROR "libnet not found")
endif()

add_library(Libnet::LIBNET UNKNOWN IMPORTED)
set_target_properties(Libnet::LIBNET PROPERTIES IMPORTED_LOCATION "${LIBNET_LIBRARIES}" INTERFACE_INCLUDE_DIRECTORIES "${LIBNET_INCLUDE_DIRS}")

