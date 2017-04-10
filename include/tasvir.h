#ifndef _TASVIR__H_
#include <net/ethernet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <uthash.h>
//#include <uuid/uuid.h>

#define TASVIR_ETH_PROTO (0x88b6)  // TODO: remove
#define TASVIR_STRLEN_MAX (32)
#define TASVIR_NR_RPC_ARGS (8)
#define TASVIR_MSG_LEN (1500)

#define TASVIR_NR_INSTANCES_AREA (128)
#define TASVIR_NR_INSTANCES_LOCAL (128)

#ifdef __cplusplus
extern "C" {
#endif

struct rte_ring;
struct rte_mempool;

// typedef uuid_t tasvir_uuid_t;
typedef char tasvir_str[TASVIR_STRLEN_MAX];
typedef struct tasvir_ring_pair tasvir_ring_pair;
typedef struct tasvir_fn_info tasvir_fn_info;
typedef struct tasvir_instance_id tasvir_instance_id;
typedef struct tasvir_node_id tasvir_node_id;
typedef struct tasvir_msg_header tasvir_msg_header;
typedef struct tasvir_msg_rpc tasvir_msg_rpc;
typedef struct tasvir_rpc_status tasvir_rpc_status;
typedef struct tasvir_instance tasvir_instance;
typedef struct tasvir_area_desc tasvir_area_desc;
typedef struct tasvir_area_header tasvir_area_header;
typedef struct tasvir_container tasvir_container;
typedef struct tasvir_local tasvir_local;
typedef struct tasvir_node tasvir_node;
typedef void (*tasvir_fnptr)(void *, void **);
typedef void (*tasvir_rpc_cb_fnptr)(tasvir_msg_rpc *);

typedef enum {
    TASVIR_MSG_TYPE_INVALID = 0,
    TASVIR_MSG_TYPE_DATA,
    TASVIR_MSG_TYPE_RPC_REQUEST,
    TASVIR_MSG_TYPE_RPC_RESPONSE
} tasvir_msg_type;

typedef enum {
    TASVIR_RPC_STATUS_INVALID = 0,
    TASVIR_RPC_STATUS_PENDING,
    TASVIR_RPC_STATUS_FAILED,
    TASVIR_RPC_STATUS_DONE
} tasvir_rpc_status_type;

typedef enum {
    TASVIR_INSTANCE_TYPE_INVALID = 0,
    TASVIR_INSTANCE_TYPE_ROOT,
    TASVIR_INSTANCE_TYPE_DAEMON,
    TASVIR_INSTANCE_TYPE_APP
} tasvir_instance_type;

typedef enum {
    TASVIR_AREA_TYPE_INVALID = 0,
    TASVIR_AREA_TYPE_CONTAINER,
    TASVIR_AREA_TYPE_NODE,
    TASVIR_AREA_TYPE_LOCAL,
    TASVIR_AREA_TYPE_APP
} tasvir_area_type;

struct tasvir_ring_pair {
    struct rte_ring *tx;
    struct rte_ring *rx;
};

struct tasvir_fn_info {
    tasvir_str name;
    tasvir_fnptr fnptr;
    uint32_t fid;
    uint8_t argc;
    int ret_len;
    size_t arg_lens[TASVIR_NR_RPC_ARGS];
    UT_hash_handle h_fid;
    UT_hash_handle h_fnptr;
};

struct tasvir_node_id {
    uint8_t ethaddr[ETHER_ADDR_LEN];
    uint32_t machine_id;
};

struct tasvir_instance_id {
    tasvir_node_id node_id;
    uint16_t port_id;
};

struct __attribute__((__packed__)) tasvir_msg_header {
    struct ether_header eh;
    /* TODO: add ip and udp header so that NIC takes care of checksum */
    tasvir_instance_id src_id;
    tasvir_instance_id dst_id;
    tasvir_msg_type type;
    uint16_t id;
};

struct __attribute__((__packed__)) tasvir_msg_rpc {
    tasvir_msg_header h;
    uint32_t fid;
    void *arg_ptrs[TASVIR_NR_RPC_ARGS];
    uint8_t data[];
};

struct tasvir_rpc_status {
    bool do_free;
    uint16_t id;
    tasvir_rpc_status_type status;
    tasvir_msg_rpc *response;
    tasvir_rpc_cb_fnptr cb;  // ignore for now
};

struct tasvir_instance {
    tasvir_instance_id id;
    uint16_t core;
    uint8_t type;
    bool active;
};

struct tasvir_area_desc {
    const tasvir_area_desc *pd;
    tasvir_area_header *h;
    size_t len;
    uint8_t type;
    const tasvir_instance *owner;
    tasvir_str name;
};

struct tasvir_area_header {
    tasvir_area_desc *d;
    uint64_t version;
    uint64_t stale_us;
    uint64_t update_us;
    uint64_t boot_us;
    size_t nr_users;
    unsigned int active : 1;
    unsigned int sync : 1;
    unsigned int pad : 6;
    tasvir_instance *users[TASVIR_NR_INSTANCES_AREA];
    uint8_t data[];
};

struct tasvir_container {
    int nr_areas;
    int nr_areas_max;
    tasvir_area_desc descs[];
};

struct tasvir_local {
    struct rte_mempool *mp;
    ptrdiff_t shadow;
    ptrdiff_t scratch;
    tasvir_ring_pair rings_discovery, rings[TASVIR_NR_INSTANCES_LOCAL];
};

struct tasvir_node {
    tasvir_node_id id;
    uint64_t tsc_hz;
    size_t nr_instances;
    tasvir_instance instances[];
};

tasvir_area_desc *tasvir_init(uint16_t core, uint8_t type);
int tasvir_sync();

tasvir_rpc_status *tasvir_rpc_async(tasvir_fnptr, ...);
void *tasvir_rpc_sync(uint64_t timeout, tasvir_fnptr, ...);
int tasvir_rpc_register(tasvir_fn_info *);
void tasvir_rpc_serve();

tasvir_area_desc *tasvir_new(tasvir_area_desc *pd, tasvir_instance *owner, uint8_t type, char *name, size_t len,
                             uint64_t stale_us, int nr_areas_max);
int tasvir_delete(tasvir_area_desc *d);
tasvir_area_desc *tasvir_attach(tasvir_area_desc *pd, char *name);
int tasvir_detach(tasvir_area_desc *d);

#ifdef __cplusplus
}
#endif
#endif /* _TASVIR__H_ */
