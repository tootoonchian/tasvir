find_package(LLVM REQUIRED CONFIG)

add_library(tasvir tasvir.c)
target_link_libraries(tasvir uuid rt ${DPDK_LIB})
target_compile_options(tasvir PUBLIC ${TASVIR_COMPILE_OPTIONS})

add_library(llvm_write_instrument MODULE llvm_log_write.cpp)
set_target_properties(llvm_write_instrument PROPERTIES COMPILE_FLAGS "-fno-rtti")
target_compile_definitions(llvm_write_instrument PUBLIC ${LLVM_DEFINITIONS})
target_compile_options(llvm_write_instrument PUBLIC -fno-rtti ${TASVIR_COMPILE_OPTIONS})
target_include_directories(llvm_write_instrument PUBLIC ${LLVM_INCLUDE_DIRS})

add_executable(daemon daemon.c)
# using set_target_properties so that duplicate Xclangs don't get removed
#set_target_properties(daemon PROPERTIES COMPILE_FLAGS "-Xclang -load -Xclang libllvm_write_instrument.so")
target_compile_options(daemon PUBLIC ${TASVIR_COMPILE_OPTIONS})
target_link_libraries(daemon tasvir rt)

add_executable(root root.c)
# using set_target_properties so that duplicate Xclangs don't get removed
#set_target_properties(root PROPERTIES COMPILE_FLAGS "-Xclang -load -Xclang libllvm_write_instrument.so")
target_compile_options(root PUBLIC ${TASVIR_COMPILE_OPTIONS})
target_link_libraries(root tasvir rt)
