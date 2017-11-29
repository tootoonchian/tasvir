# Sample mac clang-omp++ cmake call: cmake -DCMAKE_CXX_COMPILER=clang-omp++
# Regular call: cmake

cmake_minimum_required (VERSION 2.6)
project (CYCLADES CXX)

# C++11
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
CHECK_CXX_COMPILER_FLAG("-std=c++0x" COMPILER_SUPPORTS_CXX0X)
if(COMPILER_SUPPORTS_CXX11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Ofast")
elseif(COMPILER_SUPPORTS_CXX0X)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x -Ofast")
else()
        message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
endif()

# Open MP
#find_package(OpenMP)
#if (OPENMP_FOUND)
#    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
#    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
#endif()

include_directories(src)

# gflags
find_package(gflags COMPONENTS nothreads_static)

add_tasvir_exec(tasvir_cyclades src/main.cpp)
set_property(SOURCE src/main.cpp APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-all -Wno-extra")
target_link_libraries(tasvir_cyclades gflags)

#add_executable(cyclades src/main.cpp)
#add_executable(simple_ls examples/SimpleLeastSquares.cpp)
#target_link_libraries(cyclades gflags)
#target_link_libraries(simple_ls gflags)
