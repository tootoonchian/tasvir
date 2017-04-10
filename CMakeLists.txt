cmake_minimum_required(VERSION 3.0)

project(tasvir)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(TASVIR_COMPILE_OPTIONS
    -Wall -pedantic -Wextra -Wno-pointer-arith -g -O0 -march=native -D_GNU_SOURCE=1
    $<$<COMPILE_LANGUAGE:C>:-std=c11>
    $<$<COMPILE_LANGUAGE:C>:-D_POSIX_C_SOURCE=200809L>
    $<$<COMPILE_LANGUAGE:CXX>:-D__STDC_LIMIT_MACROS>
    $<$<COMPILE_LANGUAGE:CXX>:-std=c++11>)

include_directories(./include $ENV{RTE_SDK}/$ENV{RTE_TARGET}/include)
link_directories($ENV{RTE_SDK}/$ENV{RTE_TARGET}/lib ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

set(DPDK_LIB "-ldl -lpthread -Wl,--whole-archive -lrte_eal -lrte_ethdev -lrte_kvargs -lrte_mbuf -lrte_mempool -lrte_ring -lrte_pmd_i40e -lrte_pmd_ixgbe -Wl,--no-whole-archive")
add_subdirectory(src)
add_subdirectory(apps)
add_subdirectory(test)
