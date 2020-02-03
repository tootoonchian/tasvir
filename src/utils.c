#include "tasvir.h"

void tasvir_hexdump(void *addr, size_t len) {
    uint8_t *b = (uint8_t *)addr;
    size_t i;
    for (i = 0; i < len; i += 4) {
        if (i && i % 32 == 0)
            fprintf(stderr, "\n");
        fprintf(stderr, "%02X%02X%02X%02X ", b[i], b[i + 1], b[i + 2], b[i + 3]);
    }
    fprintf(stderr, "\n");
}

void tasvir_area_str(const tasvir_area_desc *d, char *buf, size_t buf_size) {
    static const char *tasvir_area_type_str[] = {"invalid", "container", "node", "app"};

    snprintf(buf, buf_size, "name=%s type=%s len=0x%lx sync_us=%lu/%lu d=%p pd=%p owner=%p h=%p flags=0x%lx", d->name,
             tasvir_area_type_str[d->type], d->len, d->sync_int_us, d->sync_ext_us, (void *)d, (void *)d->pd,
             (void *)d->owner, (void *)d->h, d->h ? d->h->flags_ : 0);
}

void tasvir_msg_str(tasvir_msg *m, bool is_src_me, bool is_dst_me, char *buf, size_t buf_size) {
    static const char *tasvir_msg_type_str[] = {"invalid", "mem", "rpc_request", "rpc_reply"};
    char direction;
    char src_str[48];
    char dst_str[48];
    tasvir_tid_str(&m->src_tid, src_str, sizeof(src_str));
    tasvir_tid_str(&m->dst_tid, dst_str, sizeof(dst_str));
    if (is_src_me)
        direction = 'O';
    else if (is_dst_me)
        direction = 'I';
    else
        direction = 'F';
    if (m->type == TASVIR_MSG_TYPE_RPC_RESPONSE || m->type == TASVIR_MSG_TYPE_RPC_REQUEST) {
        tasvir_msg_rpc *mr = (tasvir_msg_rpc *)m;
        // FIXME:insecure
        tasvir_fn_desc *fnd = &ttld.fn_descs[mr->fid];

        snprintf(buf, buf_size, "%c type=%s d=%s v=%lu id=%d %s->%s f=%s", direction, tasvir_msg_type_str[m->type],
                 m->d ? m->d->name : "root", m->version, m->id, src_str, dst_str, fnd->name);
    } else {
        tasvir_msg_mem *mm = (tasvir_msg_mem *)m;
        snprintf(buf, buf_size, "%c type=%s d=%s v=%lu id=%d %s->%s addr=%p len=%lu last=%u", direction,
                 tasvir_msg_type_str[m->type], m->d->name, m->version, m->id, src_str, dst_str, mm->addr, mm->len,
                 mm->last);
    }
#ifdef TASVIR_DEBUG_HEXDUMP
    tasvir_hexdump(&m->h.eh, m->h.mbuf.data_len);
#endif
}

void tasvir_nid_str(const tasvir_nid *nid, char *buf, UNUSED size_t buf_size) { ether_ntoa_r(&nid->mac_addr, buf); }

void tasvir_tid_str(const tasvir_tid *tid, char *buf, size_t buf_size) {
    tasvir_nid_str(&tid->nid, buf, buf_size);
    snprintf(&buf[strlen(buf)], buf_size - strlen(buf), "/i%d,p%d", tid->idx, tid->pid);
}

void tasvir_print_views(const tasvir_node *node) {
    if (!node) {
        for (size_t i = 0; i < ttld.root_desc->h->nr_users; i++)
            tasvir_print_views(ttld.root_desc->h->users[i].node);
        return;
    }
    char buf[1024];
    char node_str[1024];
    tasvir_nid_str(&node->nid, node_str, sizeof(node_str));
    int buf_size = sizeof(buf);
    for (size_t i = 0; i < node->nr_areas; i++) {
        buf_size -=
            snprintf(buf + sizeof(buf) - buf_size, buf_size, "d=%s,v=%lu ", node->areas_d[i]->name, node->areas_v[i]);
    }
    LOG_DBG("view[%s]: %s", node_str, buf);
}
