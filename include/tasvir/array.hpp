#ifndef __TASVIR_ARRAY__
#define __TASVIR_ARRAY__

#include <cstdint>
#include <functional>
#include <iostream>
#include <type_traits>

#include <tasvir/tasvir.h>

namespace tasvir {

enum class OpType {
    MAX,     // maximum
    MIN,     // minimum
    SUM,     // sum
    AVG,     // average
    PROD,    // product
    LAND,    // logical and
    BAND,    // bit-wise and
    LOR,     // logical or
    BOR,     // bit-wise or
    LXOR,    // logical xor
    BXOR,    // bit-wise xor
    MAXLOC,  // max value and location
    MINLOC,  // min value and location
};

template <typename T = double>
class Array {
   public:
    typedef T value_type;
    typedef size_t size_type;

    Array() = default;
    ~Array() = default;

    T* begin() { return data_; }
    T* end() { return data_ + size_; }

    inline T* DataLeader() { return ranks_[0]->data_; }
    inline T* Data() { return data_; }

    /* Allocate and initialize the data structure in a tasvir area.
     * Blocks until all instances are up and all areas are created
     * Call once per name.
     */
    static Array<T>* Allocate(const char* array_name, uint32_t rank, uint32_t nr_ranks, uint32_t nr_nodes,
                              std::size_t size, std::size_t capacity, uint64_t sync_int_us = 10000,
                              uint64_t sync_ext_us = 50000);

    bool Resize(std::size_t new_size) {
        if (new_size > capacity_)
            return false;
        size_ = new_size;
        return true;
    }

    void Barrier() {
        if (rank_) {
            /* wait for master to propose a new round */
            while (bcnt_ == ranks_[0]->bcnt_)
                tasvir_service_wait(S2US, false);
            bcnt_ = ranks_[0]->bcnt_;
        } else {
            bcnt_++;
        }
        tasvir_log(&bcnt_, sizeof(bcnt_));
        tasvir_service_wait(S2US, true);
        /* block for everyone to catch up */
        for (uint32_t r = 0; r < nr_ranks_; r++)
            while (bcnt_ != ranks_[r]->bcnt_)
                tasvir_service_wait(S2US, false);
    }

    template <OpType op>
    void AllReduce() {
        if (op == OpType::SUM || op == OpType::AVG) {
            tasvir_log(data_, sizeof(T) * size_);
            for (std::size_t i = 0; i < size_; i++) {
                for (uint32_t r = 0; r < nr_ranks_; r++)
                    if (r != rank_)
                        data_[i] += ranks_[r]->data_[i];
                if (op == OpType::AVG)
                    data_[i] /= nr_ranks_;
            }
        }
    }

    template <OpType>
    void Reduce() {
        if (rank_ == 0)
            return AllReduce();
    }

    template <typename Map>
    void Scatter(Map const& map) {
        for (auto const& c : map)
            std::copy(data_ + c[0], data_ + c[1], ranks_[0]->data_ + c[0]);
    }

    template <typename Map>
    void Gather(Map const& map) {
        for (auto const& c : map)
            std::copy(ranks_[0]->data_ + c[0], ranks_[0]->data_ + c[1], data_ + c[0]);
    }

   private:
    static constexpr uint64_t MS2US = 1000;
    static constexpr uint64_t S2US = 1000 * MS2US;

    size_type size_;     /* number of elements in the array */
    size_type capacity_; /* array buffer capacity in elements */

    uint32_t bcnt_;     /* barrier counter */
    uint32_t rank_;     /* rank */
    uint32_t nr_ranks_; /* number of ranks */
    uint32_t nr_nodes_; /* number of nodes */

    alignas(64) Array<T>* ranks_[256]; /* pointer to all ranks */
    alignas(64) value_type data_[1];   /* raw memory for data */
};

template <typename T>
Array<T>* Array<T>::Allocate(const char* array_name, uint32_t rank, uint32_t nr_ranks, uint32_t nr_nodes,
                             std::size_t size, std::size_t capacity, uint64_t sync_int_us, uint64_t sync_ext_us) {
    static_assert(std::is_pod<Array<T>>::value, "Array<T> is not POD.");
    static_assert(std::is_trivial<Array<T>>::value, "Array<T> is not trivial.");
    static_assert(std::is_trivially_copyable<Array<T>>::value, "Array<T> is not trivially copyable.");

    Array<T>* me;

    tasvir_area_desc* d;
    tasvir_str name;

    tasvir_area_desc param = {};
    param.len = sizeof(T) * capacity + sizeof(Array<T>);
    param.sync_int_us = sync_int_us;
    param.sync_ext_us = sync_ext_us;
    snprintf(param.name, sizeof(param.name), "%s-%lu", array_name, rank);
    if (!(d = tasvir_new(param)))
        return NULL;

    me = reinterpret_cast<Array<T>*>(tasvir_data(d));
    tasvir_log(me, sizeof(*me));
    me->size_ = size;
    me->capacity_ = capacity;
    me->nr_ranks_ = nr_ranks;
    me->nr_nodes_ = nr_nodes;
    me->rank_ = rank;
    me->bcnt_ = 2;

    uint32_t nr_local_ranks = (nr_ranks + nr_nodes - 1) / nr_nodes;
    uint32_t local_rank_b = rank / nr_local_ranks;
    uint32_t local_rank_e = rank;
    // TODO: add option to attach to RW copy
    for (uint32_t r = 0; r < nr_ranks; r++) {
        snprintf(name, sizeof(name), "%s-%lu", array_name, r);
        if (!(d = tasvir_attach_wait(5 * S2US, name)))
            return NULL;
        me->ranks_[r] = reinterpret_cast<Array<T>*>(tasvir_data(d));
    }

    tasvir_log(me, sizeof(*me));
    me->Barrier();

    return me;
}

}  // namespace tasvir
#endif
