cmake_minimum_required(VERSION 3.3)

project(tasvir VERSION 0.1.0 DESCRIPTION "Tasvir: A Shared View Network Interface")

if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to RelWithDebInfo as none was specified.")
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build type (default RelWithDebInfo)" FORCE)
endif()

string(REPLACE "-O2 -g" "-O3 -ggdb3" CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO}")
string(REPLACE "-O2 -g" "-O3 -ggdb3" CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO}" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}" CACHE STRING "" FORCE)

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
    message(FATAL_ERROR "Please invoke cmake from a build directory outside of the source directory: e.g., mkdir build; cmake ..")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ON)

include(GNUInstallDirs)

if(NOT DEFINED ENV{RTE_SDK})
    message(FATAL_ERROR "Undefined RTE_SDK env var.")
endif()
if(NOT DEFINED ENV{RTE_TARGET})
    message(FATAL_ERROR "Undefined RTE_TARGET env var.")
endif()
if(NOT EXISTS $ENV{RTE_SDK}/$ENV{RTE_TARGET})
    message(FATAL_ERROR "DPDK directory path $ENV{RTE_SDK}/$ENV{RTE_TARGET} does not exist.")
endif()

if (NOT DEFINED ENV{TASVIR_LOG_LEVEL})
    set(TASVIR_LOG_LEVEL 7)
endif()

set(TASVIR_COMPILE_OPTS
    -Wall -Wextra -pedantic
    -march=native
    -D_GNU_SOURCE=1
    -DTASVIR
    -DTASVIR_LOG_LEVEL=${TASVIR_LOG_LEVEL}
    -ffast-math
    -flto
    -fvisibility=hidden
    $<$<COMPILE_LANGUAGE:C>:-D_POSIX_C_SOURCE=200809L>
    $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
    $<$<COMPILE_LANGUAGE:CXX>:-D__STDC_LIMIT_MACROS>
    $<$<C_COMPILER_ID:GNU>:-fno-tree-loop-distribute-patterns -fno-semantic-interposition -fdiagnostics-color=always -fuse-linker-plugin>
    $<$<C_COMPILER_ID:Clang>:-fcolor-diagnostics -Wno-gnu-zero-variadic-macro-arguments -Wno-address-of-packed-member>
    )
set(TASVIR_LINK_DIRS "$ENV{RTE_SDK}/$ENV{RTE_TARGET}/lib")
set(TASVIR_LINK_LIBS dl m numa rt pthread jemalloc "-Wl,--whole-archive -ldpdk -Wl,--no-whole-archive")
set(TASVIR_LINK_OPTS -flto $<$<C_COMPILER_ID:GNU>:-fuse-linker-plugin>)

file(GLOB_RECURSE TASVIR_HDR include/*)
set(TASVIR_SRC src/alloc.c src/area.c src/dpdk.c src/init.c src/rpc.c src/service.c src/stat.c src/sync.c src/sync_internal.c src/utils.c src/tasvir.h src/utils.h)

add_executable(tasvir_daemon ${TASVIR_SRC} src/daemon.c src/sync_external.c)
target_compile_definitions(tasvir_daemon PRIVATE TASVIR_DAEMON=1)
target_compile_features(tasvir_daemon PRIVATE c_std_11 cxx_std_11)
target_compile_options(tasvir_daemon PRIVATE ${TASVIR_COMPILE_OPTS})
target_include_directories(tasvir_daemon PRIVATE include)
target_include_directories(tasvir_daemon SYSTEM PRIVATE $ENV{RTE_SDK}/$ENV{RTE_TARGET}/include)
target_link_directories(tasvir_daemon PRIVATE ${TASVIR_LINK_DIRS})
target_link_libraries(tasvir_daemon PRIVATE ${TASVIR_LINK_LIBS})
target_link_options(tasvir_daemon PRIVATE ${TASVIR_LINK_OPTS})
set_target_properties(tasvir_daemon PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(tasvir_obj OBJECT ${TASVIR_SRC})
target_compile_features(tasvir_obj PUBLIC c_std_11 cxx_std_11)
target_compile_options(tasvir_obj PUBLIC ${TASVIR_COMPILE_OPTS})
target_include_directories(tasvir_obj PUBLIC include)
target_include_directories(tasvir_obj SYSTEM PUBLIC $ENV{RTE_SDK}/$ENV{RTE_TARGET}/include)
target_link_directories(tasvir_obj PUBLIC ${TASVIR_LINK_DIRS})
target_link_libraries(tasvir_obj PUBLIC ${TASVIR_LINK_LIBS})
target_link_options(tasvir_obj PUBLIC ${TASVIR_LINK_OPTS})
set_target_properties(tasvir_obj PROPERTIES POSITION_INDEPENDENT_CODE ON PUBLIC_HEADER "${TASVIR_HDR}" VERSION ${PROJECT_VERSION})

#add_library(tasvir_shared SHARED $<TARGET_OBJECTS:tasvir_obj>)
#target_link_libraries(tasvir_shared PUBLIC tasvir_obj)
#set_target_properties(tasvir_shared PROPERTIES POSITION_INDEPENDENT_CODE ON PUBLIC_HEADER "${TASVIR_HDR}" VERSION ${PROJECT_VERSION} OUTPUT_NAME tasvir)

add_library(tasvir_static STATIC $<TARGET_OBJECTS:tasvir_obj>)
target_link_libraries(tasvir_static PUBLIC tasvir_obj)
set_target_properties(tasvir_static PROPERTIES POSITION_INDEPENDENT_CODE ON PUBLIC_HEADER "${TASVIR_HDR}" VERSION ${PROJECT_VERSION} OUTPUT_NAME tasvir)

#install(TARGETS tasvir
#        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
#        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tasvir)
install(TARGETS tasvir_daemon
        DESTINATION ${CMAKE_BINARY_DIR})
install(FILES ${CMAKE_BINARY_DIR}/tasvir.pc
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)

configure_file(tasvir.pc.in tasvir.pc @ONLY)

macro(add_tasvir_exec target)
    add_executable(${target} ${ARGN})
    set_target_properties(${target} PROPERTIES C_STANDARD 11 CXX_STANDARD 14 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO POSITION_INDEPENDENT_CODE ON)
    target_link_libraries(${target} tasvir_obj)
endmacro(add_tasvir_exec)

## for LLVM pass
#find_package(LLVM REQUIRED CONFIG)
#add_library(tasvir_pass MODULE src/llvm_pass.cpp)
#target_compile_definitions(tasvir_pass PUBLIC ${LLVM_DEFINITIONS})
#target_include_directories(tasvir_pass PUBLIC ${LLVM_INCLUDE_DIRS})

#macro(add_tasvir_instrumented_exec target)
#    add_executable(${target} ${ARGN})
#    set_source_files_properties(${ARGN} PROPERTIES OBJECT_DEPENDS tasvir_pass)
#    # using set_target_properties so that duplicate Xclangs don't get removed
#    set_target_properties(${target} PROPERTIES COMPILE_FLAGS "-Xclang -load -Xclang ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libtasvir_pass.so")
#    target_link_libraries(${target} tasvir)
#endmacro(add_tasvir_instrumented_exec)

add_subdirectory(apps)
add_subdirectory(doc)
