cmake_minimum_required(VERSION 3.0)

project(tasvir)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_DEBUG -g)
set(CMAKE_CXX_FLAGS_RELEASE "-g -Ofast")

set(TASVIR_COMPILE_OPTIONS
    -Wall -Wextra -Wno-gnu-zero-variadic-macro-arguments -pedantic
    -g -Ofast
    -march=native
    -D_GNU_SOURCE=1
    $<$<COMPILE_LANGUAGE:C>:-D_POSIX_C_SOURCE=200809L>
    $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
    $<$<COMPILE_LANGUAGE:CXX>:-D__STDC_LIMIT_MACROS>
    )

include_directories(./include $ENV{RTE_SDK}/$ENV{RTE_TARGET}/include)
link_directories($ENV{RTE_SDK}/$ENV{RTE_TARGET}/lib ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

## for LLVM pass
find_package(LLVM REQUIRED CONFIG)

## TODO: add DPDK dependency check

file(GLOB tasvir_src src/tasvir*.c)
add_library(tasvir STATIC ${tasvir_src})
set_target_properties(tasvir PROPERTIES C_STANDARD 11 CXX_STANDARD 11 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
target_link_libraries(tasvir uuid dl m rt pthread "-Wl,--whole-archive -ldpdk -Wl,--no-whole-archive")
target_compile_options(tasvir PUBLIC ${TASVIR_COMPILE_OPTIONS})

add_library(tasvir_pass MODULE src/llvm_pass.cpp)
set_target_properties(tasvir_pass PROPERTIES C_STANDARD 11 CXX_STANDARD 11 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
target_compile_definitions(tasvir_pass PUBLIC ${LLVM_DEFINITIONS})
target_compile_options(tasvir_pass PUBLIC ${TASVIR_COMPILE_OPTIONS})
target_include_directories(tasvir_pass PUBLIC ${LLVM_INCLUDE_DIRS})

macro(add_tasvir_exec target)
    add_executable(${target} ${ARGN})
    add_dependencies(${target} tasvir)

    set_target_properties(${target} PROPERTIES C_STANDARD 11 CXX_STANDARD 11 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
    target_compile_options(${target} PUBLIC ${TASVIR_COMPILE_OPTIONS})
    target_link_libraries(${target} tasvir rt numa)
endmacro(add_tasvir_exec)

macro(add_tasvir_instrumented_exec target)
    add_executable(${target} ${ARGN})
    add_dependencies(${target} tasvir tasvir_pass)

    #set_source_files_properties(${ARGN} PROPERTIES OBJECT_DEPENDS tasvir_pass)
    # using set_target_properties so that duplicate Xclangs don't get removed
    set_target_properties(${target} PROPERTIES COMPILE_FLAGS "-Xclang -load -Xclang ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libtasvir_pass.so"
                                               C_STANDARD 11 CXX_STANDARD 11 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
    target_compile_options(${target} PUBLIC ${TASVIR_COMPILE_OPTIONS})
    target_link_libraries(${target} tasvir rt numa)
endmacro(add_tasvir_instrumented_exec)

add_subdirectory(src)
add_subdirectory(apps)
