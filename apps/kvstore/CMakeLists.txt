#add_tasvir_instrumented_exec(tasvir_benchmark benchmark.cpp)
file(GLOB kv_sources . *.c)
add_tasvir_exec(kvstore ${kv_sources})
set_property(TARGET kvstore PROPERTY C_STANDARD 99)

