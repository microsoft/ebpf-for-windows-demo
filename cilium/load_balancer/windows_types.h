// This header file contains definitions in order to compile the bpf program.

#pragma once

#ifndef __BPF_TYPES_MAPPER__
#define __BPF_TYPES_MAPPER__
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 u64;
#endif

typedef unsigned long long uint64_t;
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;

typedef long long int64_t;
typedef char int8_t;
typedef int int32_t;
typedef short int16_t;

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(x) (x)
#endif

/* DIRECT:  Skip the FIB rules and go to FIB table associated with device
 * OUTPUT:  Do lookup from egress perspective; default is ingress
 */
enum
{
    BPF_FIB_LOOKUP_DIRECT = (1U << 0),
    BPF_FIB_LOOKUP_OUTPUT = (1U << 1),
};

enum
{
    BPF_F_HDR_FIELD_MASK = 0xfULL,
};

/* BPF_FUNC_l4_csum_replace flags. */
enum
{
    BPF_F_PSEUDO_HDR = (1ULL << 4),
    BPF_F_MARK_MANGLED_0 = (1ULL << 5),
    // BPF_F_MARK_ENFORCE = (1ULL << 6),
};

/* Mode for BPF_FUNC_skb_adjust_room helper. */
enum bpf_adj_room_mode
{
    BPF_ADJ_ROOM_NET,
    // BPF_ADJ_ROOM_MAC,
};

/* Key of an a BPF_MAP_TYPE_LPM_TRIE entry */
struct bpf_lpm_trie_key
{
    __u32 prefixlen; /* up to 32 for AF_INET, 128 for AF_INET6 */
    __u8 data[0];    /* Arbitrary size */
};

/* BPF_FUNC_skb_store_bytes flags. */
// enum {
// BPF_F_RECOMPUTE_CSUM = (1ULL << 0),
// BPF_F_INVALIDATE_HASH = (1ULL << 1),
// };

struct bpf_fib_lookup
{
    /* input:  network family for lookup (AF_INET, AF_INET6)
     * output: network family of egress nexthop
     */
    __u8 family;

    /* set if lookup is to consider L4 data - e.g., FIB rules */
    __u8 l4_protocol;
    __be16 sport;
    __be16 dport;

    /* total length of packet from network header - used for MTU check */
    __u16 tot_len;

    /* input: L3 device index for lookup
     * output: device index from FIB lookup
     */
    __u32 ifindex;

    union
    {
        /* inputs to lookup */
        __u8 tos;        /* AF_INET  */
        __be32 flowinfo; /* AF_INET6, flow_label + priority */

        /* output: metric of fib result (IPv4/IPv6 only) */
        __u32 rt_metric;
    };

    union
    {
        __be32 ipv4_src;
        __u32 ipv6_src[4]; /* in6_addr; network order */
    };

    /* input to bpf_fib_lookup, ipv{4,6}_dst is destination address in
     * network header. output: bpf_fib_lookup sets to gateway address
     * if FIB lookup returns gateway route
     */
    union
    {
        __be32 ipv4_dst;
        __u32 ipv6_dst[4]; /* in6_addr; network order */
    };

    /* output */
    __be16 h_vlan_proto;
    __be16 h_vlan_TCI;
    __u8 smac[6]; /* ETH_ALEN */
    __u8 dmac[6]; /* ETH_ALEN */
};

/* flags for BPF_MAP_CREATE command */
enum
{
    BPF_F_NO_PREALLOC = (1U << 0),

};
