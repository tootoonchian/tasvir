find_package(LLVM REQUIRED CONFIG)

add_library(tasvir tasvir.c)
target_link_libraries(tasvir uuid rt ${DPDK_LIB})

add_library(llvm_write_instrument MODULE llvm_log_write.cpp)
set_target_properties(llvm_write_instrument PROPERTIES
        COMPILE_FLAGS "-fno-rtti"
        )
target_compile_definitions(llvm_write_instrument PUBLIC ${LLVM_DEFINITIONS})
target_compile_options(llvm_write_instrument PUBLIC -fno-rtti)
target_include_directories(llvm_write_instrument PUBLIC ${LLVM_INCLUDE_DIRS})

add_executable(daemon daemon.c)
# using set_target_properties so that duplicate Xclangs don't get removed
set_target_properties(daemon PROPERTIES COMPILE_FLAGS "-Xclang -load -Xclang ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libllvm_write_instrument.so")
target_link_libraries(daemon tasvir rt)
