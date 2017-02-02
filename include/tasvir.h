#ifndef _TASVIR__H_
#include <net/ethernet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <uuid/uuid.h>

#define TASVIR_STRLEN_MAX (32)
#define TASVIR_NR_NODES (128)
#define TASVIR_NR_AREAS (32)
#define TASVIR_NR_AREA_INSTANCES (128)
#define TASVIR_NR_LOCAL_INSTANCES (72)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *addr;
    size_t len;
} tasvir_region;

typedef struct {
    uuid_t uuid;
    uint8_t ethaddr[6];
    bool active;
    uint32_t stale_us;
    uint64_t update_us;
} tasvir_instance;

typedef struct {
    tasvir_region shadow;
    tasvir_region data_ro;
    tasvir_region data_rw;
    char name[TASVIR_STRLEN_MAX];
    bool active;
    uint64_t version;
    uint32_t stale_us;
    uint64_t update_us;
    tasvir_instance *owner;                                  // writer instance id
    tasvir_instance *subscribers[TASVIR_NR_AREA_INSTANCES];  // ids of subscribers
} tasvir_area;

typedef struct {
    tasvir_region base;
    tasvir_region shadow;   // compact log region
    tasvir_region data_ro;  // for concurrently accessed data
    tasvir_region data_rw;
    bool active;
    uint64_t version;
    char name[TASVIR_STRLEN_MAX];
    uint32_t stale_us;
    uint64_t update_us;
    tasvir_area areas[TASVIR_NR_AREAS];
    tasvir_instance instances[TASVIR_NR_AREA_INSTANCES];
} tasvir_meta;

typedef struct {
    bool active;
    uint32_t stale_us;
    uint64_t update_us;
} tasvir_node_state;

struct rte_ring;
struct rte_mempool;
typedef struct {
    uuid_t uuid;
    uint64_t boot_us;
    uint64_t tsc_hz;
    uint8_t ethaddr[6];
    struct {
        struct rte_ring *tx;
        struct rte_ring *rx;
    } rings_local[TASVIR_NR_LOCAL_INSTANCES];
    struct {
        struct rte_ring *tx;
        struct rte_ring *rx;
    } rings_global[TASVIR_NR_NODES];
    struct rte_mempool *mp;
} tasvir_node;

int tasvir_init(int core);
int tasvir_init_daemon(int core);

tasvir_meta *tasvir_new(const char *name, size_t length);
int tasvir_delete(const tasvir_meta *meta);

tasvir_meta *tasvir_attach(const char *name);
int tasvir_detach(const tasvir_meta *meta);

int tasvir_sync(const tasvir_meta *meta);
int tasvir_sync_daemon();

tasvir_area *tasvir_area_new(const tasvir_meta *meta, const char *name, uint32_t stale_us);
int tasvir_area_delete(tasvir_area *area);
tasvir_area *tasvir_area_subscribe(const tasvir_meta *meta, const char *name);
int tasvir_area_unsubscribe(const tasvir_area *area);

#ifdef __cplusplus
}
#endif
#endif /* _TASVIR__H_ */
