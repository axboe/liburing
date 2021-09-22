cmake_minimum_required(VERSION 3.14)

project("liburing")
set(libname "uring")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

############################
## Add headers to library ##
############################
function(add_headers VAR dir)
    set(headers ${${VAR}})
    foreach (header ${ARGN})
        set(headers ${headers} ${dir}/${header})
    endforeach()
    set(${VAR} ${headers} PARENT_SCOPE)
endfunction()

add_headers(
    liburing_headers    # Variable name
    src/include         # Directory to find headers
    liburing.h
    liburing/barrier.h
    liburing/io_uring.h)

file(GLOB liburing_sources src/*.c)
# string(REPLACE ";" " " liburing_sources "${liburing_sources}")

add_library("${libname}" ${liburing_sources} ${liburing_headers})

target_include_directories(
    "${libname}"
    PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/include/>
    $<INSTALL_INTERFACE:include>)

# If we're building this project directly (rather than as a dependency), we
# have to build tests
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)

    # Run configure to generate config-host.h, if configure hasn't been run
    if(NOT EXISTS "${PROJECT_SOURCE_DIR}/config-host.h")
        execute_process(
            COMMAND "${PROJECT_SOURCE_DIR}/configure"
            WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif()

    include(CTest)

    # Tests need to be linked against pthreads
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)

    set(liburing_test_flags
        -include "${PROJECT_SOURCE_DIR}/config-host.h"
        -g
        -O2
        -D_GNU_SOURCE
        -D__SANE_USERSPACE_TYPES__
        -Wall
        -Wextra
        -Wno-unused-parameter
        -Wno-sign-compare
        -Wstringop-overflow=0
        -Warray-bounds=0)
    file(GLOB liburing_tests "test/*.c")
    # Remove the helpers.c, which doesn't contain a main
    list(FILTER liburing_tests EXCLUDE REGEX "helpers.c")
    foreach(test_file ${liburing_tests})

        # Get the name of the target. This will be the file name, stripped of
        # ".c" at the end.
        get_filename_component(target ${test_file} NAME_WLE)

        # Create an executable target for the test; add test/helpers.c as a source
        add_executable(${target} ${test_file} test/helpers.c)

        # Target liburing and pthreads
        target_link_libraries(
            ${target}
            PRIVATE
            ${libname}
            Threads::Threads)

        # Add additional compiler options and definitions
        target_compile_options(${target} PRIVATE ${liburing_test_flags})

        # Register the test with ctest
        add_test(NAME "test-${target}" COMMAND "${target}")
    endforeach()
endif()
