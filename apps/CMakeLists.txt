#add_tasvir_instrumented_exec(tasvir_benchmark benchmark.cpp)
add_tasvir_exec(tasvir_benchmark benchmark.cpp)

add_subdirectory(kvstore)
add_subdirectory(cyclades)
