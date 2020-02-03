add_tasvir_exec(tasvir_benchmark benchmark.cpp)
add_tasvir_exec(tasvir_allreduce allreduce.cpp)
add_tasvir_exec(tasvir_matrix_mkl matrix_mkl.cpp)
target_link_libraries(tasvir_matrix_mkl "-Wl,--start-group /usr/lib/x86_64-linux-gnu/libmkl_core.a /usr/lib/x86_64-linux-gnu/libmkl_intel_ilp64.a /usr/lib/x86_64-linux-gnu/libmkl_sequential.a /usr/lib/x86_64-linux-gnu/libmkl_core.a -Wl,--end-group")
