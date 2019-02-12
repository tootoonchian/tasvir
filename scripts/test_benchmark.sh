reset; RTE_SDK=$RTE_SDK ninja -C/srv/tasvir/build && for host_list in c29; do
    benchmark_area_len=$((512 * 1024 * 1024))
    benchmark_stride=16
    benchmark_nr_writers=1
    benchmark_duration_ms=5000
    benchmark_service_us=25
    benchmark_sync_int=1000
    benchmark_sync_ext=100000
    nr_workers=1
    export benchmark_area_len benchmark_stride benchmark_duration_ms benchmark_service_us nr_workers host_list
    /srv/tasvir/scripts/run.sh benchmark
done
