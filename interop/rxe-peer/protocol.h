// Versioned control records; never transmit a native C structure.
#ifndef ROCE_INTEROP_PROTOCOL_H
#define ROCE_INTEROP_PROTOCOL_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define RC_INFO_SIZE 64u
#define RC_MAX_SIZE (64u * 1024u * 1024u)
struct rc_info {
    uint8_t ipv4[4], mac[6];
    uint32_t qpn, psn, rkey;
    uint64_t address, length;
    uint16_t mtu, udp_port;
    uint8_t retry, rnr_retry, timeout, read_depth, responder_depth, rnr_timer;
};
static uint64_t get_be(const uint8_t *p, size_t n) {
    uint64_t value = 0;
    for (size_t i = 0; i < n; ++i) value = (value << 8) | p[i];
    return value;
}
static void put_be(uint8_t *p, uint64_t value, size_t n) {
    for (size_t i = n; i > 0; --i) { p[i - 1] = (uint8_t)value; value >>= 8; }
}
static bool valid_mtu(uint16_t mtu) {
    return mtu == 256 || mtu == 512 || mtu == 1024 || mtu == 2048 || mtu == 4096;
}
static bool info_valid(const struct rc_info *v) {
    return v->qpn >= 2 && v->qpn <= 0xffffff && v->psn <= 0xffffff &&
        valid_mtu(v->mtu) && v->length <= UINT64_MAX - v->address &&
        v->retry <= 7 && v->rnr_retry <= 7 && v->timeout <= 31 &&
        v->rnr_timer <= 31 && v->read_depth == 1 && v->responder_depth == 1 &&
        v->udp_port >= 49152 && v->ipv4[0] != 0 && v->ipv4[0] < 224;
}
static bool info_encode(const struct rc_info *v, uint8_t out[RC_INFO_SIZE]) {
    if (!info_valid(v)) return false;
    memset(out, 0, RC_INFO_SIZE);
    memcpy(out, "RCV2", 4); put_be(out + 4, 1, 2); put_be(out + 6, RC_INFO_SIZE, 2);
    memcpy(out + 8, v->ipv4, 4); memcpy(out + 12, v->mac, 6);
    put_be(out + 18, v->mtu, 2); put_be(out + 20, v->qpn, 4);
    put_be(out + 24, v->psn, 4); put_be(out + 28, v->rkey, 4);
    put_be(out + 32, v->address, 8); put_be(out + 40, v->length, 8);
    out[48] = v->retry; out[49] = v->rnr_retry; out[50] = v->timeout;
    out[51] = v->read_depth; out[52] = v->responder_depth; out[53] = v->rnr_timer;
    put_be(out + 54, v->udp_port, 2);
    return true;
}
static bool info_decode(const uint8_t *in, size_t n, struct rc_info *v) {
    if (n != RC_INFO_SIZE || memcmp(in, "RCV2", 4) || get_be(in + 4, 2) != 1 ||
        get_be(in + 6, 2) != RC_INFO_SIZE) return false;
    for (size_t i = 56; i < RC_INFO_SIZE; ++i) if (in[i]) return false;
    memset(v, 0, sizeof(*v));
    memcpy(v->ipv4, in + 8, 4); memcpy(v->mac, in + 12, 6);
    v->mtu = (uint16_t)get_be(in + 18, 2); v->qpn = (uint32_t)get_be(in + 20, 4);
    v->psn = (uint32_t)get_be(in + 24, 4); v->rkey = (uint32_t)get_be(in + 28, 4);
    v->address = get_be(in + 32, 8); v->length = get_be(in + 40, 8);
    v->retry = in[48]; v->rnr_retry = in[49]; v->timeout = in[50];
    v->read_depth = in[51]; v->responder_depth = in[52]; v->rnr_timer = in[53];
    v->udp_port = (uint16_t)get_be(in + 54, 2);
    return info_valid(v);
}
static uint8_t pattern(size_t offset, uint32_t iteration) {
    return (uint8_t)(((uint64_t)offset * 131 + (uint64_t)iteration * 17) ^ (offset >> 8));
}
#endif
