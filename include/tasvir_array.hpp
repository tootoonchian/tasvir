#ifndef __TASVIR_ARRAY__
#define __TASVIR_ARRAY__

#include <cstdint>
#include <iostream>
#include <type_traits>

#include "tasvir.h"

namespace tasvir {

template <typename T = double>
class Array {
public:
    typedef T value_type;
    typedef size_t size_type;

    Array() = default;
    ~Array() = default;

    inline T* DataMaster() { return _master->_data; }
    inline T* DataWorker() { return _data; }

    /* Allocate and initialize the data structure in a tasvir area.
     * Blocks until all instances are up and all areas are created
     * Call once per prefix.
     */
    static Array<T>* Allocate(const char* prefix, uint64_t wid, std::size_t nr_workers, std::size_t nr_elements);

    void Barrier() {
        std::size_t wid;
        _done = _version;
        tasvir_log_write(&_done, sizeof(_done));
        tasvir_service_wait(5 * 1000 * 1000);

        if (_wid == 0) {
            for (wid = 0; wid < _nr_workers; wid++)
                while (_workers[wid]->_done != _master->_version) {
                    tasvir_service();
                }
            _master->_done = _master->_version;
            _master->_version++;
            tasvir_log_write(&_master->_done, sizeof(_done));
            tasvir_log_write(&_master->_version, sizeof(_version));
        }

        /* block until master changes version */
        while (_done == _master->_version)
            tasvir_service();

        _version = _master->_version;
        tasvir_log_write(&_version, sizeof(_version));
    }

    void ReduceAdd() {
        if (_wid != 0)
            return;
        tasvir_log_write(_master->_data, sizeof(double) * _size);
        std::fill(_master->_data, _master->_data + _size, 0);
        for (std::size_t w = 0; w < _nr_workers; w++) {
            for (int i = 0; i < _size; i++) {
                _master->_data[i] += _workers[w]->_data[i];
            }
        }
    }

    template <typename Map>
    void ReduceSelect(const Map& map) {
        for (const auto& c : map)
            std::copy(&_data[c[0]], &_data[c[1]], &_master->_data[c[0]]);
    }

    template <typename Map>
    void CopySelect(const Map& map) {
        for (const auto& c : map)
            std::copy(&_master->_data[c[0]], &_master->_data[c[1]], &_data[c[0]]);
    }

private:
    size_type _size; /* the number of elements in the array */

    std::size_t _nr_workers; /* number of workers under this */
    uint64_t _wid;           /* thread identifier */
    uint64_t _version;       /* version we are processing now */
    uint64_t _done;          /* version we finished processing last */
    uint64_t _initialized;   /* sentinel to ensure initialization */

    alignas(64) Array<T>* _master;   /* pointer to the master */
    Array<T>* _workers[1024];        /* pointer to workers each with their own version of the data */
    alignas(64) value_type _data[1]; /* raw memory for data */
};

// FIXME: stolen from web
uint64_t hash(uint64_t x) {
    x += (uint64_t)0xbf58476d1ce4e5b9;
    x = (x ^ (x >> 30)) * (uint64_t)0xbf58476d1ce4e5b9;
    x = (x ^ (x >> 27)) * (uint64_t)0x94d049bb133111eb;
    x = x ^ (x >> 31);
    return x;
}

template <typename T>
Array<T>* Array<T>::Allocate(const char* prefix, uint64_t wid, std::size_t nr_workers, std::size_t nr_elements) {
    static_assert(std::is_trivially_copyable<Array<T>>::value, "Array<T> is not trivially copyable.");

    Array<T>* master;
    Array<T>* worker;

    tasvir_area_desc* root_desc = tasvir_attach(NULL, "root", NULL, false);
    if (!root_desc) {
        std::cerr << "tasvir_attach to root failed" << std::endl;
        abort();
    }
    tasvir_area_desc* d;
    tasvir_str name;

    tasvir_area_desc param = {};
    param.pd = root_desc;
    param.owner = NULL;
    param.type = TASVIR_AREA_TYPE_APP;
    param.len = sizeof(T) * nr_elements + sizeof(Array<T>);
    param.stale_us = 50000;
    snprintf(param.name, sizeof(param.name), "%s-%d", prefix, wid);
    d = tasvir_new(param);
    if (!d) {
        std::cerr << "tasvir_new failed" << std::endl;
        abort();
    }

    worker = reinterpret_cast<Array<T>*>(tasvir_data(d));
    tasvir_log_write(worker, sizeof(*worker));
    worker->_size = nr_elements;
    worker->_nr_workers = 0;
    worker->_wid = wid;
    worker->_version = 1;
    worker->_done = 0;
    worker->_initialized = hash(wid);

    if (wid == 0) {
        param.pd = root_desc;
        param.owner = NULL;
        param.type = TASVIR_AREA_TYPE_APP;
        param.len = sizeof(T) * nr_elements + sizeof(Array<T>);
        param.stale_us = 50000;
        snprintf(param.name, sizeof(param.name), "%s-master", prefix);
        d = tasvir_new(param);
        if (!d) {
            std::cerr << "tasvir_new master failed" << std::endl;
            abort();
        }
        master = reinterpret_cast<Array<T>*>(tasvir_data(d));
        master->_size = nr_elements;
        master->_nr_workers = nr_workers;
        master->_wid = wid;
        master->_version = 1;
        master->_done = 0;

        for (std::size_t i = 0; i < nr_workers; i++) {
            snprintf(name, sizeof(name), "%s-%d", prefix, i);
            d = tasvir_attach_wait(root_desc, name, NULL, i == wid, 5 * 1000 * 1000);
            if (!d) {
                std::cerr << "tasvir_attach " << name << " failed" << std::endl;
                abort();
            }
            master->_workers[i] = reinterpret_cast<Array<T>*>(tasvir_data(d));
            while (!master->_workers[i] || master->_workers[i]->_initialized != hash(i))
                tasvir_service();
        }
        master->_initialized = hash(0);
        tasvir_log_write(master, sizeof(*master));
        tasvir_service_wait(5 * 1000 * 1000);
    } else {
        tasvir_service_wait(5 * 1000 * 1000);
        snprintf(name, sizeof(name), "%s-master", prefix);
        d = tasvir_attach_wait(root_desc, name, NULL, true, 5 * 1000 * 1000);
        if (!d) {
            std::cerr << "tasvir_attach " << name << " failed" << std::endl;
            abort();
        }
        master = reinterpret_cast<Array<T>*>(tasvir_data(d));
        while (master->_initialized != hash(0))
            tasvir_service();
    }

    tasvir_log_write(worker, sizeof(*worker));
    worker->_master = master;
    worker->_nr_workers = master->_nr_workers;
    std::copy(master->_workers, master->_workers + nr_workers, worker->_workers);
    worker->Barrier();

    return worker;
}

}  // namespace tasvir
#endif
