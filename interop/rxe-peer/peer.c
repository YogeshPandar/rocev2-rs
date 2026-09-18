// Standalone verbs reference peer; not linked into the Rust transport.
#define _POSIX_C_SOURCE 200809L
#include "protocol.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <infiniband/verbs.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define DEADLINE_MS 20000u
static uint64_t milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) { perror("clock_gettime"); exit(1); }
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}
static bool number(const char *text, uint64_t maximum, uint64_t *out) {
    if (!text[0] || text[0] == '-' || text[0] == '+') return false;
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 0);
    if (errno || !end || *end || value > maximum) return false;
    *out = (uint64_t)value;
    return true;
}
static bool wait_fd(int fd, short events, uint64_t deadline) {
    for (;;) {
        uint64_t now = milliseconds();
        if (now >= deadline) { errno = ETIMEDOUT; return false; }
        struct pollfd p = { .fd = fd, .events = events };
        int rc = poll(&p, 1, (int)(deadline - now));
        if (rc < 0 && errno == EINTR) continue;
        if (rc <= 0) { if (!rc) errno = ETIMEDOUT; return false; }
        if (p.revents & events) return true;
        errno = ECONNRESET; return false;
    }
}
static bool exchange_bytes(int fd, void *buffer, size_t length, bool writing) {
    uint8_t *bytes = buffer;
    const uint64_t deadline = milliseconds() + DEADLINE_MS;
    for (size_t done = 0; done < length;) {
        if (!wait_fd(fd, writing ? POLLOUT : POLLIN, deadline)) return false;
        ssize_t n = writing ? send(fd, bytes + done, length - done, MSG_NOSIGNAL | MSG_DONTWAIT)
                            : recv(fd, bytes + done, length - done, MSG_DONTWAIT);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n <= 0) { if (!n) errno = ECONNRESET; return false; }
        done += (size_t)n;
    }
    return true;
}
static bool token(int fd, uint8_t value, bool writing) {
    uint8_t actual = value;
    return exchange_bytes(fd, &actual, 1, writing) && actual == value;
}
static enum ibv_mtu verbs_mtu(uint16_t value) {
    switch (value) {
        case 256: return IBV_MTU_256;
        case 512: return IBV_MTU_512;
        case 1024: return IBV_MTU_1024;
        case 2048: return IBV_MTU_2048;
        default: return IBV_MTU_4096;
    }
}
static int select_gid(struct ibv_context *ctx, uint8_t port, const struct ibv_port_attr *attr, const uint8_t ip[4]) {
    const uint8_t prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    for (int index = 0; index < attr->gid_tbl_len && index <= UINT8_MAX; ++index) {
        struct ibv_gid_entry entry;
        if (!ibv_query_gid_ex(ctx, port, (uint32_t)index, &entry, 0) &&
            entry.gid_type == IBV_GID_TYPE_ROCE_V2 &&
            !memcmp(entry.gid.raw, prefix, 12) && !memcmp(entry.gid.raw + 12, ip, 4)) return index;
    }
    fprintf(stderr, "no IPv4-mapped RoCEv2 GID for the selected port/address\n");
    return -1;
}
static bool connect_qp(struct ibv_qp *qp, uint8_t port, int gid, const struct rc_info *local, const struct rc_info *remote) {
    struct ibv_qp_attr a = {0};
    a.qp_state = IBV_QPS_INIT; a.port_num = port; a.pkey_index = 0;
    a.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    if (ibv_modify_qp(qp, &a, IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS)) return false;
    memset(&a, 0, sizeof(a));
    a.qp_state = IBV_QPS_RTR;
    a.path_mtu = verbs_mtu(local->mtu < remote->mtu ? local->mtu : remote->mtu);
    a.dest_qp_num = remote->qpn; a.rq_psn = remote->psn;
    a.max_dest_rd_atomic = 1; a.min_rnr_timer = local->rnr_timer;
    a.ah_attr.is_global = 1; a.ah_attr.port_num = port;
    a.ah_attr.grh.dgid.raw[10] = 0xff; a.ah_attr.grh.dgid.raw[11] = 0xff;
    memcpy(a.ah_attr.grh.dgid.raw + 12, remote->ipv4, 4);
    a.ah_attr.grh.sgid_index = (uint8_t)gid; a.ah_attr.grh.hop_limit = 64;
    if (ibv_modify_qp(qp, &a, IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
                     IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER)) return false;
    memset(&a, 0, sizeof(a));
    a.qp_state = IBV_QPS_RTS; a.sq_psn = local->psn;
    a.timeout = local->timeout; a.retry_cnt = local->retry; a.rnr_retry = local->rnr_retry; a.max_rd_atomic = 1;
    return !ibv_modify_qp(qp, &a, IBV_QP_STATE | IBV_QP_SQ_PSN | IBV_QP_TIMEOUT |
                         IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC);
}
static bool completion(struct ibv_cq *cq, enum ibv_wc_opcode opcode, uint64_t id, uint32_t size, bool receive) {
    const uint64_t deadline = milliseconds() + DEADLINE_MS;
    do {
        struct ibv_wc wc;
        int n = ibv_poll_cq(cq, 1, &wc);
        if (n < 0) return false;
        if (n) {
            if (wc.status != IBV_WC_SUCCESS) {
                fprintf(stderr, "WC failure id=%" PRIu64 " status=%s vendor=%u\n", wc.wr_id, ibv_wc_status_str(wc.status), wc.vendor_err);
                return false;
            }
            return wc.wr_id == id && wc.opcode == opcode && (!receive || wc.byte_len == size);
        }
    } while (milliseconds() < deadline);
    fprintf(stderr, "completion deadline expired\n");
    return false;
}
static int self_test(void) {
    struct rc_info a = { .ipv4 = {192, 0, 2, 1}, .qpn = 2, .psn = 0xfffff0,
        .rkey = 0x12345678, .address = 0x0102030405060708, .length = 4096, .mtu = 1024,
        .udp_port = 49152, .retry = 6, .rnr_retry = 7, .timeout = 14,
        .read_depth = 1, .responder_depth = 1, .rnr_timer = 1 }, b;
    uint8_t encoded[RC_INFO_SIZE], again[RC_INFO_SIZE];
    if (!info_encode(&a, encoded) || !info_decode(encoded, sizeof(encoded), &b) || !info_encode(&b, again) || memcmp(encoded, again, sizeof(encoded))) return 1;
    for (size_t n = 0; n < sizeof(encoded); ++n) if (info_decode(encoded, n, &b)) return 1;
    for (size_t i = 56; i < sizeof(encoded); ++i) {
        encoded[i] = 1; if (info_decode(encoded, sizeof(encoded), &b)) return 1; encoded[i] = 0;
    }
    for (size_t i = 0; i < sizeof(encoded); ++i) printf("%02x", encoded[i]);
    putchar('\n');
    return 0;
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--self-test")) return self_test();
    if (argc != 10 && argc != 11) {
        fprintf(stderr, "usage: %s DEVICE IPV4 TCP_PORT OP(1=send,2=write,3=read) REQUESTER(0/1) SIZE MTU PSN ITERATIONS [IB_PORT]\n", argv[0]);
        return 2;
    }
    uint64_t values[8] = {0};
    const uint64_t maxima[8] = {65535, 3, 1, RC_MAX_SIZE, 4096, 0xffffff, 1000000, 255};
    for (int i = 0; i < argc - 3; ++i) if (!number(argv[i + 3], maxima[i], &values[i])) { fprintf(stderr, "invalid numeric argument\n"); return 2; }
    const uint16_t tcp_port = (uint16_t)values[0], mtu = (uint16_t)values[4];
    const uint8_t operation = (uint8_t)values[1], port = argc == 11 ? (uint8_t)values[7] : 1;
    const bool requester = values[2] != 0;
    const uint32_t size = (uint32_t)values[3], iterations = (uint32_t)values[6];
    if (!tcp_port || !operation || !valid_mtu(mtu) || !iterations || !port) return 2;
    struct rc_info local = { .mtu = mtu, .psn = (uint32_t)values[5], .retry = 6,
        .rnr_retry = 6, .timeout = 14, .read_depth = 1, .responder_depth = 1,
        .rnr_timer = 1, .udp_port = 49152 }, remote;
    if (inet_pton(AF_INET, argv[2], local.ipv4) != 1) return 2;
    struct ibv_device **devices = NULL;
    struct ibv_context *ctx = NULL; struct ibv_pd *pd = NULL; struct ibv_cq *cq = NULL;
    struct ibv_qp *qp = NULL; struct ibv_mr *mr = NULL; uint8_t *buffer = NULL;
    int listener = -1, fd = -1, result = 1;
    devices = ibv_get_device_list(NULL);
    if (!devices) goto cleanup;
    for (size_t i = 0; devices[i]; ++i) if (!strcmp(ibv_get_device_name(devices[i]), argv[1])) { ctx = ibv_open_device(devices[i]); break; }
    if (!ctx) { fprintf(stderr, "device not found or inaccessible\n"); goto cleanup; }
    struct ibv_port_attr attr;
    if (ibv_query_port(ctx, port, &attr) || attr.state != IBV_PORT_ACTIVE || attr.link_layer != IBV_LINK_LAYER_ETHERNET || attr.active_mtu < verbs_mtu(mtu)) goto cleanup;
    int gid = select_gid(ctx, port, &attr, local.ipv4);
    if (gid < 0) goto cleanup;
    pd = ibv_alloc_pd(ctx); cq = ibv_create_cq(ctx, 16, NULL, NULL, 0);
    buffer = calloc(size ? size : 1, 1);
    if (!pd || !cq || !buffer) goto cleanup;
    mr = ibv_reg_mr(pd, buffer, size ? size : 1, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
    if (!mr) goto cleanup;
    struct ibv_qp_init_attr init = { .send_cq = cq, .recv_cq = cq, .qp_type = IBV_QPT_RC,
        .cap = { .max_send_wr = 8, .max_recv_wr = 8, .max_send_sge = 1, .max_recv_sge = 1 } };
    qp = ibv_create_qp(pd, &init);
    if (!qp) goto cleanup;
    local.qpn = qp->qp_num; local.rkey = mr->rkey; local.address = (uintptr_t)buffer; local.length = size ? size : 1;
    uint8_t encoded[RC_INFO_SIZE], request[16] = {0};
    if (!info_encode(&local, encoded)) goto cleanup;
    listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) goto cleanup;
    int one = 1;
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) goto cleanup;
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons(tcp_port) };
    memcpy(&address.sin_addr, local.ipv4, 4);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) || listen(listener, 1)) goto cleanup;
    // The orchestrator waits for this line without opening a probe connection.
    puts("LISTENING"); fflush(stdout);
    if (!wait_fd(listener, POLLIN, milliseconds() + DEADLINE_MS)) goto cleanup;
    struct sockaddr_in client; socklen_t client_length = sizeof(client);
    fd = accept(listener, (struct sockaddr *)&client, &client_length);
    if (fd < 0) goto cleanup;
    if (!exchange_bytes(fd, request, sizeof(request), false) || memcmp(request, "RQT1", 4) ||
        request[4] != operation || request[5] != (uint8_t)!requester || request[6] || request[7] ||
        get_be(request + 8, 4) != size || get_be(request + 12, 4) != iterations) goto cleanup;
    if (!exchange_bytes(fd, encoded, sizeof(encoded), true) || !exchange_bytes(fd, encoded, sizeof(encoded), false) ||
        !info_decode(encoded, sizeof(encoded), &remote) || remote.length < size ||
        memcmp(remote.ipv4, &client.sin_addr, 4) || !connect_qp(qp, port, gid, &local, &remote)) goto cleanup;
    for (uint32_t iteration = 0; iteration < iterations; ++iteration) {
        bool source = (requester && operation != 3) || (!requester && operation == 3);
        for (size_t i = 0; i < size; ++i) buffer[i] = source ? pattern(i, iteration) : 0xa5;
        struct ibv_sge sge = { .addr = (uintptr_t)buffer, .length = size, .lkey = mr->lkey };
        if (!requester && operation == 1) {
            struct ibv_recv_wr recv = { .wr_id = iteration, .sg_list = &sge, .num_sge = 1 }, *bad;
            if (ibv_post_recv(qp, &recv, &bad)) goto cleanup;
        }
        // Both QPs are RTS and SEND receives are posted before the barrier.
        if (!token(fd, 'R', true) || !token(fd, 'R', false)) goto cleanup;
        if (requester) {
            struct ibv_send_wr send = { .wr_id = iteration, .sg_list = &sge, .num_sge = 1, .send_flags = IBV_SEND_SIGNALED }, *bad;
            send.opcode = operation == 1 ? IBV_WR_SEND : operation == 2 ? IBV_WR_RDMA_WRITE : IBV_WR_RDMA_READ;
            if (operation != 1) { send.wr.rdma.remote_addr = remote.address; send.wr.rdma.rkey = remote.rkey; }
            enum ibv_wc_opcode expected = operation == 1 ? IBV_WC_SEND : operation == 2 ? IBV_WC_RDMA_WRITE : IBV_WC_RDMA_READ;
            if (ibv_post_send(qp, &send, &bad) || !completion(cq, expected, iteration, size, false)) goto cleanup;
        } else if (operation == 1 && !completion(cq, IBV_WC_RECV, iteration, size, true)) goto cleanup;
        if (!requester && !token(fd, 'D', false)) goto cleanup;
        if (!source) for (size_t i = 0; i < size; ++i) if (buffer[i] != pattern(i, iteration)) {
            fprintf(stderr, "payload mismatch iteration=%u offset=%zu\n", iteration, i); goto cleanup;
        }
        if (requester) { if (!token(fd, 'D', true) || !token(fd, 'K', false)) goto cleanup; }
        else if (!token(fd, 'K', true)) goto cleanup;
    }
    printf("{\"peer\":\"verbs\",\"operation\":%u,\"requester\":%s,\"size\":%u,\"iterations\":%u,\"mtu\":%u,\"status\":\"pass\"}\n",
           operation, requester ? "true" : "false", size, iterations, mtu);
    result = 0;
cleanup:
    if (result) fprintf(stderr, "peer failed: %s\n", strerror(errno));
    if (fd >= 0) close(fd);
    if (listener >= 0) close(listener);
    // Stop DMA before deregistration or freeing memory; fail closed on teardown errors.
    if (qp && ibv_destroy_qp(qp)) return 1;
    if (mr && ibv_dereg_mr(mr)) return 1;
    free(buffer);
    if (cq && ibv_destroy_cq(cq)) result = 1;
    if (pd && ibv_dealloc_pd(pd)) result = 1;
    if (ctx && ibv_close_device(ctx)) result = 1;
    if (devices) ibv_free_device_list(devices);
    return result;
}
