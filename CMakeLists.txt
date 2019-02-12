cmake_minimum_required(VERSION 3.3)

project(tasvir VERSION 0.1.0 DESCRIPTION "Tasvir: A Shared View Network Interface")

include(GNUInstallDirs)

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
    message(FATAL_ERROR "Please invoke cmake from a build directory outside of the source directory: e.g., mkdir build; cmake ..")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

if(NOT DEFINED ENV{RTE_SDK})
    message(FATAL_ERROR "Undefined RTE_SDK env var.")
endif()
if(NOT DEFINED ENV{RTE_TARGET})
    message(FATAL_ERROR "Undefined RTE_TARGET env var.")
endif()
if(NOT EXISTS $ENV{RTE_SDK}/$ENV{RTE_TARGET})
    message(FATAL_ERROR "DPDK directory path $ENV{RTE_SDK}/$ENV{RTE_TARGET} does not exist.")
endif()

include_directories(tasvir_obj SYSTEM PUBLIC $ENV{RTE_SDK}/$ENV{RTE_TARGET}/include)
link_directories($ENV{RTE_SDK}/$ENV{RTE_TARGET}/lib)

set(TASVIR_COMPILE_OPTIONS
    -Wall -Wextra -pedantic
    -march=native
    -D_GNU_SOURCE=1
    -fno-tree-loop-distribute-patterns
    -fno-semantic-interposition
    -fvisibility=hidden
    -flto
    $<$<COMPILE_LANGUAGE:C>:-D_POSIX_C_SOURCE=200809L>
    $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
    $<$<COMPILE_LANGUAGE:CXX>:-D__STDC_LIMIT_MACROS>
    $<$<C_COMPILER_ID:GNU>:-fdiagnostics-color=always>
    $<$<C_COMPILER_ID:Clang>:-fcolor-diagnostics -Wno-gnu-zero-variadic-macro-arguments>
    -Ofast
    )
set(TASVIR_LINK_OPTIONS
    -flto)

file(GLOB_RECURSE tasvir_public_headers include/*)
file(GLOB tasvir_src src/*.[ch])
list(REMOVE_ITEM tasvir_src src/daemon.c)
add_library(tasvir_obj OBJECT ${tasvir_src})
target_compile_features(tasvir_obj PUBLIC c_std_11 cxx_std_11)
target_compile_options(tasvir_obj PUBLIC ${TASVIR_COMPILE_OPTIONS})
target_include_directories(tasvir_obj PUBLIC include)
target_link_libraries(tasvir_obj PUBLIC dl m rt pthread "-Wl,--whole-archive -ldpdk -Wl,--no-whole-archive" ${TASVIR_LINK_OPTIONS})
set_target_properties(tasvir_obj PROPERTIES POSITION_INDEPENDENT_CODE 1 PUBLIC_HEADER "${tasvir_public_headers}" VERSION ${PROJECT_VERSION})

add_library(tasvir SHARED $<TARGET_OBJECTS:tasvir_obj>)
target_link_libraries(tasvir PUBLIC tasvir_obj)
set_target_properties(tasvir PROPERTIES POSITION_INDEPENDENT_CODE 1 PUBLIC_HEADER "${tasvir_public_headers}" VERSION ${PROJECT_VERSION})

add_library(tasvir_static STATIC $<TARGET_OBJECTS:tasvir_obj>)
target_link_libraries(tasvir_static PUBLIC tasvir_obj)
set_target_properties(tasvir_static PROPERTIES POSITION_INDEPENDENT_CODE 1 PUBLIC_HEADER "${tasvir_public_headers}" VERSION ${PROJECT_VERSION})

add_executable(tasvir_daemon ${tasvir_src} src/daemon.c)
target_compile_definitions(tasvir_daemon PRIVATE TASVIR_DAEMON=1)
set_target_properties(tasvir_daemon PROPERTIES POSITION_INDEPENDENT_CODE 1)
target_compile_features(tasvir_daemon PRIVATE c_std_11 cxx_std_11)
target_compile_options(tasvir_daemon PRIVATE ${TASVIR_COMPILE_OPTIONS})
target_include_directories(tasvir_daemon PRIVATE include)
target_link_libraries(tasvir_daemon PRIVATE dl m rt pthread "-Wl,--whole-archive -ldpdk -Wl,--no-whole-archive" ${TASVIR_LINK_OPTIONS})

install(TARGETS tasvir
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tasvir)
install(TARGETS tasvir_daemon
        DESTINATION ${CMAKE_BINARY_DIR})
install(FILES ${CMAKE_BINARY_DIR}/tasvir.pc
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)

configure_file(tasvir.pc.in tasvir.pc @ONLY)

macro(add_tasvir_exec target)
    add_executable(${target} ${ARGN})
    set_target_properties(${target} PROPERTIES C_STANDARD 11 CXX_STANDARD 11 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
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
