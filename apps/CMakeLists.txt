find_package(LLVM REQUIRED CONFIG)

add_executable(test_ctrl test_ctrl.c)
# using set_target_properties so that duplicate Xclangs don't get removed
#set_target_properties(test_ctrl PROPERTIES COMPILE_FLAGS "-Xclang -load -Xclang libllvm_write_instrument.so")
target_compile_options(test_ctrl PUBLIC ${TASVIR_COMPILE_OPTIONS})
target_link_libraries(test_ctrl tasvir rt)
