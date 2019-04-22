#ifndef __TASVIR_MUX__
#define __TASVIR_MUX__

#include <cstdint>
#include <iostream>

#include "tasvir.h"

namespace tasvir {

template <typename T>
class Mux {
public:
    // typedef T* iterator;
    typedef T value_type;
    typedef size_t size_type;

    Mux() = default;
    ~Mux() {}

    /* Allocate and initialize the data structure in a tasvir area.
     * Blocks until all instances are up and all areas are created
     * Call once per prefix.
     */
    static Mux<T>* Allocate(const char* prefix, uint64_t tid, std::size_t nr_workers, std::size_t nr_elements);

    void Barrier() {
        std::size_t wid;
        _done = _version;
        tasvir_log(&_done, sizeof(_done));
        tasvir_service_wait(5 * 1000 * 1000, true);

        if (_tid == 0) {
            for (wid = 0; wid < _nr_workers; wid++)
                while (_workers[wid]->_done != _master->_version)
                    tasvir_service();
            _master->_done = _master->_version;
            _master->_version++;
            tasvir_log(&_master->_done, sizeof(_done));
            tasvir_log(&_master->_version, sizeof(_version));
        }

        /* block until master changes version */
        while (_done == _master->_version)
            tasvir_service();

        _version = _master->_version;
        tasvir_log(&_version, sizeof(_version));
    }

    inline T* Select() { return NULL; }

private:
    size_type _size; /* the number of elements in the array */

    std::size_t _nr_workers; /* number of workers under this */
    uint64_t _tid;           /* thread identifier */
    uint64_t _version;       /* version we are processing now */
    uint64_t _done;          /* version we finished processing last */
    uint64_t _initialized;   /* sentinel to ensure initialization */

    alignas(64) Mux<T>* _master;     /* pointer to the master */
    Mux<T>* _workers[1024];          /* pointer to workers each with their own version of the data */
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
Mux<T>* Mux<T>::Allocate(const char* prefix, uint64_t tid, std::size_t nr_workers, std::size_t nr_elements) {
    return NULL;
}

}  // namespace tasvir
#endif
