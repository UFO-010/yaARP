
cmake_minimum_required(VERSION 3.5)

project(example LANGUAGES C CXX)

add_library(${PROJECT_NAME}_compiler_flags INTERFACE)
add_library(${PROJECT_NAME}_compiler_flags_c INTERFACE)
add_library(${PROJECT_NAME}_compiler_flags_cxx INTERFACE)

add_subdirectory(../ yaARP)


set(SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/main.cpp"
)

add_executable(${PROJECT_NAME} ${SOURCES} )

find_library(yaARP yaARP PATH_SUFFIXES yaARP)

target_link_libraries(${PROJECT_NAME} PRIVATE
    ${PROJECT_NAME}_compiler_flags
    yaARP
)

target_link_libraries(${PROJECT_NAME}_compiler_flags INTERFACE ${PROJECT_NAME}_compiler_flags_c)
target_compile_features(${PROJECT_NAME}_compiler_flags INTERFACE c_std_11)
target_link_libraries(${PROJECT_NAME}_compiler_flags INTERFACE ${PROJECT_NAME}_compiler_flags_cxx)
target_compile_features(${PROJECT_NAME}_compiler_flags INTERFACE cxx_std_17)
