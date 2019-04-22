set(kv_sources alloc.c alloc_dict.c dict.c main.c siphash.c)
add_tasvir_exec(kvstore ${kv_sources})
target_compile_definitions(kvstore PRIVATE NO_LOG=0 NO_SERVICE=0)

add_tasvir_exec(kvstore-nolog ${kv_sources})
target_compile_definitions(kvstore-nolog PRIVATE NO_LOG=1 NO_SERVICE=0)

add_tasvir_exec(kvstore-nosync ${kv_sources})
set_property(TARGET kvstore-nosync PROPERTY C_STANDARD 11)
target_compile_definitions(kvstore-nosync PRIVATE NO_LOG=0 NO_SERVICE=1)

add_tasvir_exec(kvstore-nothing ${kv_sources})
set_property(TARGET kvstore-nothing PROPERTY C_STANDARD 11)
target_compile_definitions(kvstore-nothing PRIVATE NO_LOG=1 NO_SERVICE=1)

set(kvbench_sources alloc.c alloc_dict.c dict.c main-putget.c siphash.c)
add_tasvir_exec(kvbench ${kvbench_sources})
