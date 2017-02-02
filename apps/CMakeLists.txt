find_package(LLVM REQUIRED CONFIG)

add_executable(test_ctrl test_ctrl.c)
target_link_libraries(test_ctrl tasvir rt)
# using set_target_properties so that duplicate Xclangs don't get removed
set_target_properties(test_ctrl PROPERTIES COMPILE_FLAGS "-Xclang -load -Xclang ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libllvm_write_instrument.so")
