// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <map>
#include <string>
#include <io.h>

#include "daemon.h"
#include "map.h"
#include "util.h"

#define TCP_TRAFFIC_TIMEOUT 20

#pragma region("maps updated by daemon")
#define DEFAULT_MAP_PIN_PATH_PREFIX "/ebpf/global/"
#define LB4_BACKEND_MAP_V2 "cilium_lb4_backends"
#define LB6_BACKEND_MAP_V2 "cilium_lb6_backends"
#define CILIUM_LB_MAP_MAX_ENTRIES 65536

#define LB4_MAGLEV_MAP_INNER "cilium_lb4_maglev_inner"
#define LB6_MAGLEV_MAP_INNER "cilium_lb6_maglev_inner"
#define LB4_MAGLEV_MAP_OUTER "cilium_lb4_maglev"
#define LB6_MAGLEV_MAP_OUTER "cilium_lb6_maglev"

#define LB4_SERVICES_MAP_V2 "cilium_lb4_services_v2"
#define LB6_SERVICES_MAP_V2 "cilium_lb6_services_v2"

#define LB4_REVERSE_NAT_MAP "cilium_lb4_reverse_nat"
#define LB6_REVERSE_NAT_MAP "cilium_lb6_reverse_nat"

#define NODEPORT_NEIGH4 "cilium_nodeport_neigh4"
#define NODEPORT_NEIGH4_SIZE 524288
#define NODEPORT_NEIGH6 "cilium_nodeport_neigh6"
#define NODEPORT_NEIGH6_SIZE 524288

#define CT_MAP_TCP4 "cilium_ct4_global"
#define CT_MAP_SIZE_TCP 4096

#pragma endregion

#pragma region("maps created by XDP program")
#pragma endregion

#define serviceFlagExternalIPs 1 << 0
#define serviceFlagRoutable 1 << 6
#define serviceFlagSessionAffinity 1 << 4

static std::string _pinned_maps[] = {
    std::string("cilium_xdp_scratch"),
    std::string("cilium_ktime_cache"),
    std::string("cilium_lxc"),
    std::string("cilium_metrics"),
    std::string("cilium_calls_xdp"),
    std::string("cilium_ipcache"),
    std::string("cilium_ipv4_frag_datagrams"),
    std::string("cilium_ct_any4_global"),
    std::string("cilium_ct_any6_global"),
    std::string("cilium_ct4_global"),
    std::string("cilium_ct6_global"),
    std::string("cilium_snat_v4_external"),
    std::string(LB6_SERVICES_MAP_V2),
    std::string("cilium_lb6_reverse_nat"),
    std::string("cilium_lb6_backends"),
    std::string("cilium_lb6_source_range"),
    std::string("cilium_lb6_maglev"),
    std::string(LB4_SERVICES_MAP_V2),
    std::string("cilium_lb4_source_range"),
    std::string(LB4_MAGLEV_MAP_OUTER),
    std::string("cilium_capture4_rules"),
    std::string("cilium_capture6_rules"),
    std::string("cilium_nodeport_neigh4"),
    std::string("cilium_nodeport_neigh6"),
    std::string("cilium_snat_v6_external"),
    std::string("cilium_lb4_reverse_nat"),
    std::string("cilium_lb4_backends"),
    std::string("CODE_FLOW_TRACK"),
    std::string("CODE_FLOW_TRACK_COUNT"),
    std::string("cilium_encrypt_state")};

uint8_t service_flags = serviceFlagExternalIPs | serviceFlagRoutable | serviceFlagSessionAffinity;

typedef uint32_t __be32;
typedef uint16_t __be16;
typedef uint16_t __u16;

typedef enum connection_state
{
    active,
    closing,
    idle
} connection_state_t;

typedef struct statistics_entry
{
    __be32 daddr;
    __be32 saddr;
    __be16 dport;
    __be16 sport;
    __be32 backend_ip;
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 tx_bytes;
    connection_state_t state;
} statistics_entry_t;

typedef struct ipv4_ct_tuple
{
    /* Address fields are reversed, i.e.,
     * these field names are correct for reply direction traffic.
     */
    __be32 daddr;
    __be32 saddr;
    /* The order of dport+sport must not be changed!
     * These field names are correct for original direction traffic.
     */
    __be16 dport;
    __be16 sport;
    __u8 nexthdr;
    __u8 flags;
} ipv4_ct_tuple_t;

typedef struct ct_entry
{
    __u64 rx_packets;
    /* Previously, the rx_bytes field was not used for entries with
     * the dir=CT_SERVICE (see GH#7060). Therefore, we can safely abuse
     * this field to save the backend_id.
     */
    union
    {
        __u64 rx_bytes;
        __u64 backend_id;
    };
    __u64 tx_packets;
    __u64 tx_bytes;
    __u32 lifetime;
    __u16 rx_closing : 1, tx_closing : 1, nat46 : 1, lb_loopback : 1, seen_non_syn : 1, node_port : 1,
        proxy_redirect : 1, /* Connection is redirected to a proxy */
        dsr : 1, reserved : 8;
    __u16 rev_nat_index;
    /* In the kernel ifindex is u32, so we need to check in cilium-agent
     * that ifindex of a NodePort device is <= MAX(u16).
     */
    __u16 ifindex;

    /* *x_flags_seen represents the OR of all TCP flags seen for the
     * transmit/receive direction of this entry.
     */
    __u8 tx_flags_seen;
    __u8 rx_flags_seen;

    __u32 src_sec_id; /* Used from userspace proxies, do not change offset! */

    /* last_*x_report is a timestamp of the last time a monitor
     * notification was sent for the transmit/receive direction.
     */
    __u32 last_tx_report;
    __u32 last_rx_report;
} ct_entry_t;

typedef struct lb4_backend_value
{
    __be32 address; /* Service endpoint IPv4 address */
    __be16 port;    /* L4 port filter */
    __u8 proto;     /* L4 protocol, currently not used (set to 0) */
    __u8 pad;
} lb4_backend_value_t;

union v6addr
{
    struct
    {
        __u32 p1;
        __u32 p2;
        __u32 p3;
        __u32 p4;
    } p;
    struct
    {
        __u64 d1;
        __u64 d2;
    } d;
    __u8 addr[IPV6_ADDRESS_LENGTH];
} __packed;

typedef struct lb6_backend_value
{
    union v6addr address;
    __be16 port;
    __u8 proto;
    __u8 pad;
} lb6_backend_value_t;

typedef struct map_properties
{
    fd_t map_fd;
    ebpf_map_type_t map_type;
    int key_size;
    int value_size;
    int max_entries;
} map_properties_t;

typedef struct lb4_key
{
    __be32 address;     /* Service virtual IPv4 address */
    __be16 dport;       /* L4 port filter, if unset, all ports apply */
    __u16 backend_slot; /* Backend iterator, 0 indicates the svc frontend */
    __u8 proto;         /* L4 protocol, currently not used (set to 0) */
    __u8 scope;         /* LB_LOOKUP_SCOPE_* for externalTrafficPolicy=Local */
    __u8 pad[2];
} lb4_key_t;

typedef struct lb4_service
{
    union
    {
        __u32 backend_id;       /* Backend ID in lb4_backends */
        __u32 affinity_timeout; /* In seconds, only for svc frontend */
    };
    /* For the service frontend, count denotes number of service backend
     * slots (otherwise zero).
     */
    __u16 count;
    __u16 rev_nat_index; /* Reverse NAT ID in lb4_reverse_nat */
    __u8 flags;
    __u8 flags2;
    __u8 pad[2];
} lb4_service_t;

typedef struct lb6_key
{
    union v6addr address; /* Service virtual IPv6 address */
    __be16 dport;         /* L4 port filter, if unset, all ports apply */
    __u16 backend_slot;   /* Backend iterator, 0 indicates the svc frontend */
    __u8 proto;           /* L4 protocol, currently not used (set to 0) */
    __u8 scope;           /* LB_LOOKUP_SCOPE_* for externalTrafficPolicy=Local */
    __u8 pad[2];
} lb6_key_t;

/* See lb4_service comments */
typedef struct lb6_service
{
    union
    {
        __u32 backend_id;       /* Backend ID in lb6_backends */
        __u32 affinity_timeout; /* In seconds, only for svc frontend */
    };
    __u16 count;
    __u16 rev_nat_index;
    __u8 flags;
    __u8 flags2;
    __u8 pad[2];
} lb6_service_t;

typedef struct lb4_reverse_nat
{
    __be32 address;
    __be16 port;
} lb4_reverse_nat_t;

typedef struct lb6_reverse_nat
{
    union v6addr address;
    __be16 port;
} lb6_reverse_nat_t;

std::map<std::string, map_properties_t> map_name_to_properties;

uint32_t
create_or_get_map_fd(std::string map_name)
{
    return 0;
}

uint32_t
initialize_map_entries()
{
    try {
        // Insert all the eBPF maps needed for Cilium.

        // Backend maps.
        map_name_to_properties[std::string(LB4_BACKEND_MAP_V2)] = {
            ebpf_fd_invalid,
            BPF_MAP_TYPE_HASH,
            sizeof(uint32_t),
            sizeof(lb4_backend_value_t),
            CILIUM_LB_MAP_MAX_ENTRIES};
        map_name_to_properties[std::string(LB6_BACKEND_MAP_V2)] = {
            ebpf_fd_invalid,
            BPF_MAP_TYPE_HASH,
            sizeof(uint32_t),
            sizeof(lb6_backend_value_t),
            CILIUM_LB_MAP_MAX_ENTRIES};

        // Maglev outer maps.
        map_name_to_properties[std::string(LB4_MAGLEV_MAP_OUTER)] = {
            ebpf_fd_invalid, BPF_MAP_TYPE_HASH_OF_MAPS, sizeof(uint16_t), sizeof(uint32_t), CILIUM_LB_MAP_MAX_ENTRIES};
        map_name_to_properties[std::string(LB6_MAGLEV_MAP_OUTER)] = {
            ebpf_fd_invalid, BPF_MAP_TYPE_HASH_OF_MAPS, sizeof(uint16_t), sizeof(uint32_t), CILIUM_LB_MAP_MAX_ENTRIES};

        // Services maps.
        map_name_to_properties[std::string(LB4_SERVICES_MAP_V2)] = {
            ebpf_fd_invalid, BPF_MAP_TYPE_HASH, sizeof(lb4_key_t), sizeof(lb4_service_t), CILIUM_LB_MAP_MAX_ENTRIES};
        map_name_to_properties[std::string(LB6_SERVICES_MAP_V2)] = {
            ebpf_fd_invalid, BPF_MAP_TYPE_HASH, sizeof(lb6_key_t), sizeof(lb6_service_t), CILIUM_LB_MAP_MAX_ENTRIES};

        // Reverse NAT maps.
        map_name_to_properties[std::string(LB4_REVERSE_NAT_MAP)] = {
            ebpf_fd_invalid, BPF_MAP_TYPE_HASH, sizeof(uint16_t), sizeof(lb4_reverse_nat_t), CILIUM_LB_MAP_MAX_ENTRIES};
        map_name_to_properties[std::string(LB6_REVERSE_NAT_MAP)] = {
            ebpf_fd_invalid, BPF_MAP_TYPE_HASH, sizeof(uint16_t), sizeof(lb6_reverse_nat_t), CILIUM_LB_MAP_MAX_ENTRIES};

        // Neighbor entry maps.
        map_name_to_properties[std::string(NODEPORT_NEIGH4)] = {
            ebpf_fd_invalid, BPF_MAP_TYPE_LRU_HASH, sizeof(__be32), sizeof(mac_address_t), NODEPORT_NEIGH4_SIZE};
        map_name_to_properties[std::string(NODEPORT_NEIGH6)] = {
            ebpf_fd_invalid, BPF_MAP_TYPE_LRU_HASH, sizeof(union v6addr), sizeof(mac_address_t), NODEPORT_NEIGH6_SIZE};

        // Connection track maps.
        map_name_to_properties[std::string(CT_MAP_TCP4)] = {
            ebpf_fd_invalid, BPF_MAP_TYPE_HASH, sizeof(ipv4_ct_tuple_t), sizeof(ct_entry_t), CT_MAP_SIZE_TCP};
    } catch (...) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    return ERROR_SUCCESS;
}

std::string
get_map_pin_path(const char* map_name)
{
    std::string map_path = std::string(DEFAULT_MAP_PIN_PATH_PREFIX);
    map_path += map_name;

    return map_path;
}

fd_t
get_map_fd(const char* map_name)
{
    // First check if the map fd is cached.
    std::map<std::string, map_properties_t>::iterator it;
    it = map_name_to_properties.find(std::string(map_name));
    if (it == map_name_to_properties.end()) {
        // We should never be here.
        return ebpf_fd_invalid;
    }
    if (it->second.map_fd != ebpf_fd_invalid) {
        return it->second.map_fd;
    }

    // Map fd is invalid. Open fd to the map.
    std::string pin_path = get_map_pin_path(map_name);
    fd_t fd = bpf_obj_get(pin_path.c_str());
    if (fd != ebpf_fd_invalid) {
        it->second.map_fd = fd;
        return fd;
    }

    printf("get_map_fd: pinned map not found, creating new map %s\n", map_name);

    // Map not created yet. Create and pin the map.
    fd = bpf_map_create(it->second.map_type, nullptr, it->second.key_size, it->second.value_size, it->second.max_entries, 0);
    if (fd > 0) {
        // Map created. Now pin the map.
        int error = bpf_obj_pin(fd, pin_path.c_str());
        if (error != 0) {
            // close map fd.
            _close(fd);
            return ebpf_fd_invalid;
        }

        it->second.map_fd = fd;
        return fd;
    }

    return ebpf_fd_invalid;
}

uint32_t
add_backend_node_to_backend_map(backend_t* backend_node)
{
    lb4_backend_value_t v4_value = {0};
    lb6_backend_value_t v6_value = {0};
    void* value = nullptr;
    const char* map_name = backend_node->family == AF_INET ? LB4_BACKEND_MAP_V2 : LB6_BACKEND_MAP_V2;
    fd_t map_fd = get_map_fd(map_name);
    if (map_fd == ebpf_fd_invalid) {
        return ERROR_NOT_FOUND;
    }

    if (backend_node->family == AF_INET) {
        v4_value.address = backend_node->address_bytes.v4_address;
        v4_value.port = _byteswap_ushort(backend_node->port);
        value = &v4_value;
    } else {
        memcpy(&v6_value.address, backend_node->address_bytes.v6_address, IPV6_ADDRESS_LENGTH);
        v6_value.port = _byteswap_ushort(backend_node->port);
        value = &v6_value;
    }

    return bpf_map_update_elem(map_fd, &backend_node->id, value, 0);
}

uint32_t
remove_backend_node_from_backend_map(backend_t* backend_node)
{
    const char* map_name = backend_node->family == AF_INET ? LB4_BACKEND_MAP_V2 : LB6_BACKEND_MAP_V2;
    fd_t map_fd = get_map_fd(map_name);
    if (map_fd == ebpf_fd_invalid) {
        return ERROR_NOT_FOUND;
    }

    return bpf_map_delete_elem(map_fd, &backend_node->id);
}

uint32_t
delete_maglev_table_from_map(bool ipv6, uint16_t rev_nat_id)
{
    uint32_t result = 0;
    const char* outer_map_name = ipv6 ? LB6_MAGLEV_MAP_OUTER : LB4_MAGLEV_MAP_OUTER;
    fd_t outer_map_fd = get_map_fd(outer_map_name);
    if (outer_map_fd == ebpf_fd_invalid) {
        return ERROR_NOT_FOUND;
    }

    // Delete inner map from the outer map.
    result = bpf_map_delete_elem(outer_map_fd, &rev_nat_id);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

Exit:
    return result;
}

uint32_t
update_maglev_table_to_map(bool ipv6, uint16_t rev_nat_id, std::vector<uint32_t>& backend_ids)
{
    uint32_t result = 0;
    const char* outer_map_name = ipv6 ? LB6_MAGLEV_MAP_OUTER : LB4_MAGLEV_MAP_OUTER;
    fd_t outer_map_fd = get_map_fd(outer_map_name);
    if (outer_map_fd == ebpf_fd_invalid) {
        return ERROR_NOT_FOUND;
    }

    // Create inner maglev map
    fd_t inner_map_fd =
        bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(uint32_t), sizeof(uint32_t) * MAGLEV_TABLE_SIZE, 1, 0);
    if (inner_map_fd == ebpf_fd_invalid) {
        return ERROR_NOT_FOUND;
    }

    // Update entry in inner maglev map
    uint32_t key = 0;
    result = bpf_map_update_elem(inner_map_fd, &key, backend_ids.data(), 0);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

    // Add the inner map in the outer map.
    result = bpf_map_update_elem(outer_map_fd, &rev_nat_id, &inner_map_fd, 0);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

    // Inner map is added to the outer map, so it is safe to close fd for the inner map.
    _close(inner_map_fd);
    inner_map_fd = ebpf_fd_invalid;

Exit:
    if (result != ERROR_SUCCESS) {
        if (inner_map_fd != ebpf_fd_invalid) {
            _close(inner_map_fd);
        }
    }
    return result;
}

uint32_t
delete_service_endpoints(service_t* service)
{
    uint32_t result = ERROR_SUCCESS;
    lb4_key_t v4_key = {0};
    lb6_key_t v6_key = {0};
    uint16_t slot;
    bool ipv4 = service->frontend.family == AF_INET ? true : false;

    const char* map_name = ipv4 ? LB4_SERVICES_MAP_V2 : LB4_SERVICES_MAP_V2;
    fd_t map_fd = get_map_fd(map_name);
    if (map_fd == ebpf_fd_invalid) {
        return ERROR_NOT_FOUND;
    }

    if (ipv4) {
        v4_key.dport = _byteswap_ushort(service->frontend.port);
        v4_key.proto = protocol_t::any;
        v4_key.address = service->frontend.address_bytes.v4_address;
    } else {
        v6_key.dport = _byteswap_ushort(service->frontend.port);
        v6_key.proto = protocol_t::any;
        memcpy(&v6_key.address, service->frontend.address_bytes.v6_address, IPV6_ADDRESS_LENGTH);
    }

    slot = 1;

    // Iterate over all backends and insert entries in the map.
    for (int i = 0; i < service->backends.size(); i++) {
        if (ipv4) {
            v4_key.backend_slot = slot;
        } else {
            v6_key.backend_slot = slot;
        }

        void* key = ipv4 ? (void*)&v4_key : (void*)&v6_key;

        result = bpf_map_delete_elem(map_fd, key);
        if (result != ERROR_SUCCESS) {
            break;
        }
        slot++;
    }

    return result;
}

uint32_t
update_service_endpoints(service_t* service)
{
    uint32_t result = ERROR_SUCCESS;
    lb4_key_t v4_key = {0};
    lb6_key_t v6_key = {0};
    lb4_service_t v4_value = {0};
    lb6_service_t v6_value = {0};
    uint16_t slot;
    bool ipv4 = service->frontend.family == AF_INET ? true : false;

    const char* map_name = ipv4 ? LB4_SERVICES_MAP_V2 : LB4_SERVICES_MAP_V2;
    fd_t map_fd = get_map_fd(map_name);
    if (map_fd == ebpf_fd_invalid) {
        return ERROR_NOT_FOUND;
    }

    if (ipv4) {
        v4_key.dport = _byteswap_ushort(service->frontend.port);
        v4_key.proto = protocol_t::any;
        v4_key.address = service->frontend.address_bytes.v4_address;
    } else {
        v6_key.dport = _byteswap_ushort(service->frontend.port);
        v6_key.proto = protocol_t::any;
        memcpy(&v6_key.address, service->frontend.address_bytes.v6_address, IPV6_ADDRESS_LENGTH);
    }

    slot = 1;

    // Iterate over all backends and insert entries in the map.
    for (backend_t& backend : service->backends) {
        if (ipv4) {
            v4_value.backend_id = backend.id;
            v4_value.rev_nat_index = (__u16)service->id;
            v4_key.backend_slot = slot;
        } else {
            v6_value.backend_id = backend.id;
            v6_value.rev_nat_index = (__u16)service->id;
            v6_key.backend_slot = slot;
        }

        void* key = ipv4 ? (void*)&v4_key : (void*)&v6_key;
        void* value = ipv4 ? (void*)&v4_value : (void*)&v6_value;

        result = bpf_map_update_elem(map_fd, key, value, 0);
        if (result != ERROR_SUCCESS) {
            break;
        }
        slot++;
    }

    return result;
}

uint32_t
remove_reverse_nat(service_t* service)
{
    uint16_t key = (uint16_t)service->id;

    bool ipv4 = service->frontend.family == AF_INET ? true : false;
    const char* map_name = ipv4 ? LB4_REVERSE_NAT_MAP : LB6_REVERSE_NAT_MAP;
    fd_t map_fd = get_map_fd(map_name);
    if (map_fd == ebpf_fd_invalid) {
        return ERROR_NOT_FOUND;
    }

    return bpf_map_delete_elem(map_fd, &key);
}

uint32_t
update_reverse_nat(service_t* service)
{
    uint32_t result = ERROR_SUCCESS;
    uint16_t key = (uint16_t)service->id;
    lb4_reverse_nat_t v4_value = {0};
    lb6_reverse_nat_t v6_value = {0};

    bool ipv4 = service->frontend.family == AF_INET ? true : false;
    const char* map_name = ipv4 ? LB4_REVERSE_NAT_MAP : LB6_REVERSE_NAT_MAP;
    fd_t map_fd = get_map_fd(map_name);
    if (map_fd == ebpf_fd_invalid) {
        return ERROR_NOT_FOUND;
    }

    if (ipv4) {
        v4_value.port = _byteswap_ushort(service->frontend.port);
        v4_value.address = service->frontend.address_bytes.v4_address;
    } else {
        v6_value.port = _byteswap_ushort(service->frontend.port);
        memcpy(&v6_value.address, service->frontend.address_bytes.v6_address, IPV6_ADDRESS_LENGTH);
    }

    void* value = ipv4 ? (void*)&v4_value : (void*)&v6_value;
    result = bpf_map_update_elem(map_fd, &key, value, 0);

    return result;
}

uint32_t
update_master_service(service_t* service)
{
    uint32_t result = ERROR_SUCCESS;
    lb4_key_t v4_key = {0};
    lb6_key_t v6_key = {0};
    lb4_service_t v4_value = {0};
    lb6_service_t v6_value = {0};
    bool ipv4 = service->frontend.family == AF_INET ? true : false;

    const char* map_name = ipv4 ? LB4_SERVICES_MAP_V2 : LB4_SERVICES_MAP_V2;
    fd_t map_fd = get_map_fd(map_name);
    if (map_fd == ebpf_fd_invalid) {
        return ERROR_NOT_FOUND;
    }

    if (ipv4) {
        v4_key.dport = _byteswap_ushort(service->frontend.port);
        v4_key.proto = protocol_t::any;
        // "service" already contains address in BE.
        v4_key.address = service->frontend.address_bytes.v4_address;

        v4_value.rev_nat_index = (__u16)service->id;
        v4_value.count = (__u16)service->backends.size();
        v4_value.flags = service_flags;
    } else {
        v6_key.dport = _byteswap_ushort(service->frontend.port);
        v6_key.proto = protocol_t::any;
        memcpy(&v6_key.address, service->frontend.address_bytes.v6_address, IPV6_ADDRESS_LENGTH);

        v6_value.rev_nat_index = (__u16)service->id;
        v6_value.count = (__u16)service->backends.size();
        v6_value.flags = service_flags;
    }

    void* key = ipv4 ? (void*)&v4_key : (void*)&v6_key;
    void* value = ipv4 ? (void*)&v4_value : (void*)&v6_value;

    result = bpf_map_update_elem(map_fd, key, value, 0);

    return result;
}

uint32_t
remove_master_service(service_t* service)
{
    lb4_key_t v4_key = {0};
    lb6_key_t v6_key = {0};
    bool ipv4 = service->frontend.family == AF_INET ? true : false;

    const char* map_name = ipv4 ? LB4_SERVICES_MAP_V2 : LB4_SERVICES_MAP_V2;
    fd_t map_fd = get_map_fd(map_name);
    if (map_fd == ebpf_fd_invalid) {
        return ERROR_NOT_FOUND;
    }

    if (ipv4) {
        v4_key.dport = _byteswap_ushort(service->frontend.port);
        v4_key.proto = protocol_t::any;
        // "service" already contains address in BE.
        v4_key.address = service->frontend.address_bytes.v4_address;
    } else {
        v6_key.dport = _byteswap_ushort(service->frontend.port);
        v6_key.proto = protocol_t::any;
        memcpy(&v6_key.address, service->frontend.address_bytes.v6_address, IPV6_ADDRESS_LENGTH);
    }

    void* key = ipv4 ? (void*)&v4_key : (void*)&v6_key;

    return bpf_map_delete_elem(map_fd, key);
}

uint32_t
update_neighbor_entry(ADDRESS_FAMILY family, _In_ const address_bytes_t* address, _In_ const mac_address_t* mac_address)
{
    uint32_t result = ERROR_SUCCESS;
    __be32 v4_key;
    union v6addr v6_key;

    bool ipv4 = family == AF_INET ? true : false;
    const char* map_name = ipv4 ? NODEPORT_NEIGH4 : NODEPORT_NEIGH6;
    fd_t map_fd = get_map_fd(map_name);
    if (map_fd == ebpf_fd_invalid) {
        return ERROR_NOT_FOUND;
    }

    if (ipv4) {
        v4_key = address->v4_address;
    } else {
        memcpy(v6_key.addr, address->v6_address, IPV6_ADDRESS_LENGTH);
    }

    void* key = ipv4 ? (void*)&v4_key : (void*)&v6_key;
    const void* value = mac_address;

    result = bpf_map_update_elem(map_fd, key, value, 0);

    return result;
}

uint32_t
delete_neighbor_entry(ADDRESS_FAMILY family, _In_ const address_bytes_t* address)
{
    uint32_t result = ERROR_SUCCESS;
    __be32 v4_key;
    union v6addr v6_key;

    bool ipv4 = family == AF_INET ? true : false;
    const char* map_name = ipv4 ? NODEPORT_NEIGH4 : NODEPORT_NEIGH6;
    fd_t map_fd = get_map_fd(map_name);
    if (map_fd == ebpf_fd_invalid) {
        return ERROR_NOT_FOUND;
    }

    if (ipv4) {
        v4_key = address->v4_address;
    } else {
        memcpy(v6_key.addr, address->v6_address, IPV6_ADDRESS_LENGTH);
    }

    void* key = ipv4 ? (void*)&v4_key : (void*)&v6_key;

    result = bpf_map_delete_elem(map_fd, key);

    return result;
}

uint32_t
clean_old_pinned_maps()
{
    // First unpin any pinned maps.
    uint32_t array_size = sizeof(_pinned_maps) / sizeof(_pinned_maps[0]);
    for (uint32_t i = 0; i < array_size; i++) {
        std::string pin_path = get_map_pin_path(_pinned_maps[i].c_str());
        ebpf_object_unpin(pin_path.c_str());
    }

    // Now close the map fds that are open.
    for (auto& map : map_name_to_properties) {
        if (map.second.map_fd != ebpf_fd_invalid) {
            _close(map.second.map_fd);
            map.second.map_fd = ebpf_fd_invalid;
        }
    }
    return ERROR_SUCCESS;
}

uint32_t
get_total_map_count()
{
    ebpf_id_t start_id = 0;
    ebpf_id_t end_id = 0;
    uint32_t map_count = 0;
    while (bpf_map_get_next_id(start_id, &end_id) == 0) {
        map_count++;
        start_id = end_id;
    }

    return map_count;
}

uint32_t
get_total_program_count()
{
    ebpf_id_t start_id = 0;
    ebpf_id_t end_id = 0;
    uint32_t map_count = 0;
    while (bpf_prog_get_next_id(start_id, &end_id) == 0) {
        map_count++;
        start_id = end_id;
    }

    return map_count;
}

uint32_t
update_neighbor_map_for_destination(_In_ const char* destination_address)
{
    uint32_t result = ERROR_SUCCESS;
    address_bytes_t address_bytes;
    ADDRESS_FAMILY family;
    mac_address_t next_hop_mac_address;
    std::string destination_address_string(destination_address);

    // Convert IP string to bytes.
    result = string_to_address(destination_address_string, &address_bytes, &family);
    if (result != ERROR_SUCCESS) {
        result = ERROR_INVALID_PARAMETER;
        goto Exit;
    }

    result = get_next_hop_mac_address(family, &address_bytes, &next_hop_mac_address);
    if (result != ERROR_SUCCESS) {
        printf("destination %s is not reachable.\n", destination_address);
        goto Exit;
    }

    result = update_neighbor_entry(family, &address_bytes, &next_hop_mac_address);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }
    printf("Updated neighbor entry for destination %s\n", destination_address);

Exit:
    return result;
}

static void
print_connection_entry(_In_ const statistics_entry_t* entry)
{
    const char* state = nullptr;
    if (entry->state == active) {
        state = "ACTIVE";
    } else if (entry->state == idle) {
        state = "IDLE";
    } else {
        state = "CLOSING";
    }

    printf(
        "%12s  %12s%9s%9s  %12s%9s%9s%9s\n",
        integer_to_v4_address_string(entry->saddr).c_str(),
        integer_to_v4_address_string(entry->daddr).c_str(),
        std::to_string(_byteswap_ushort(entry->sport)).c_str(),
        std::to_string(_byteswap_ushort(entry->dport)).c_str(),
        integer_to_v4_address_string(entry->backend_ip).c_str(),
        state,
        std::to_string(entry->rx_bytes).c_str(),
        std::to_string(entry->tx_bytes).c_str());
}

static void
_print_header()
{
    printf("\n");
    printf("                             Source     Dest                              Rx       Tx\n");
    printf("   Source IP      Dest. IP     Port     Port    Backend IP    State    Bytes    Bytes\n");
    printf("============  ============  =======  =======  ============  =======  =======  =======\n");
}

static void
_print_trailer()
{
    printf("\n\n");
}

static bool
_is_entry_closing(ct_entry_t* entry)
{
    return entry->rx_closing || entry->tx_closing;
}

uint32_t
print_ipv4_connection_track_entries(_In_ const service_t* service)
{
    uint32_t result;
    ipv4_ct_tuple_t v4_key = {0};
    uint32_t entry_count = 0;
    uint32_t array_size = 0;
    ipv4_ct_tuple_t* keys = nullptr;
    ct_entry_t* values = nullptr;
    uint32_t current_time;
    fd_t map_fd = get_map_fd(CT_MAP_TCP4);
    if (map_fd == ebpf_fd_invalid) {
        return ERROR_NOT_FOUND;
    }

    // Make a first pass to get the total number of entries.
    result = bpf_map_get_next_key(map_fd, nullptr, &v4_key);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

    while (true) {
        entry_count++;
        result = bpf_map_get_next_key(map_fd, &v4_key, &v4_key);
        if (result != ERROR_SUCCESS) {
            break;
        }
    }

    array_size = 2 * entry_count;
    entry_count = 0;
    // Allocate memory for those many keys and values.
    keys = (ipv4_ct_tuple_t*)malloc(array_size * sizeof(ipv4_ct_tuple_t));
    if (keys == nullptr) {
        result = ERROR_NOT_ENOUGH_MEMORY;
        goto Exit;
    }
    values = (ct_entry_t*)malloc(array_size * sizeof(ct_entry_t));
    if (values == nullptr) {
        result = ERROR_NOT_ENOUGH_MEMORY;
        goto Exit;
    }

    // Make second pass on the keys and store them in the allocated arrays.
    result = bpf_map_get_next_key(map_fd, nullptr, &keys[0]);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

    for (uint32_t i = 1; i < array_size; i++) {
        entry_count++;

        result = bpf_map_lookup_elem(map_fd, &keys[i - 1], &values[i - 1]);
        if (result != ERROR_SUCCESS) {
            goto Exit;
        }

        result = bpf_map_get_next_key(map_fd, &keys[i - 1], &keys[i]);
        if (result != ERROR_SUCCESS) {
            break;
        }
    }

    _print_header();

    current_time = get_current_time_seconds_since_boot();

    // Now we have all the keys and the values. Filter for the keys we are interested in.
    for (uint32_t i = 0; i < entry_count; i++) {
        // Check if the "daddr" matches the service VIP
        if (keys[i].daddr == service->frontend.address_bytes.v4_address) {
            // We have a match. Now find a reverse entry for this.
            bool dont_skip = false;
            uint32_t last_report = 0;
            bool entry_found = false;
            bool backend_found = false;
            uint32_t j;
            statistics_entry_t stats = {0};

            for (j = 0; j < entry_count; j++) {
                if (keys[i].saddr == keys[j].daddr && keys[i].dport == keys[j].sport) {
                    entry_found = true;
                    break;
                }
            }
            uint32_t index = entry_found ? j : i;

            // If the last traffic was seen TCP_TRAFFIC_TIMEOUT seconds ago, dont skip this.
            last_report = values[index].last_rx_report > values[index].last_tx_report ? values[index].last_rx_report
                                                                                      : values[index].last_tx_report;
            if (last_report + TCP_TRAFFIC_TIMEOUT > current_time) {
                dont_skip = true;
            }

            if (!dont_skip) {
                // If the connection is closing, skip it for printing.
                if (_is_entry_closing(&values[index])) {
                    continue;
                }

                // If the entry lifetime has expired, skip it.
                if (current_time > values[index].lifetime) {
                    continue;
                }

                // If no non-syn packet seen, skip the entry.
                if (!values[index].seen_non_syn) {
                    continue;
                }
            }

            stats.saddr = keys[i].saddr;
            stats.daddr = keys[i].daddr;
            stats.sport = keys[i].dport;
            stats.dport = keys[i].sport;
            if (_is_entry_closing(&values[index])) {
                stats.state = closing;
            } else if (!values[index].seen_non_syn) {
                stats.state = idle;
            } else {
                stats.state = active;
            }

            if (entry_found) {
                // We found the matching reverese entry. Merge both entries to
                // create a statistics entry.
                stats.rx_packets = values[j].rx_packets;
                stats.rx_bytes = values[j].rx_bytes;
                stats.tx_packets = values[j].tx_packets;
                stats.tx_bytes = values[j].tx_bytes;
            }

            // Get backend IP from backend ID.
            for (const auto& backend : service->backends) {
                if (backend.id == values[i].backend_id) {
                    stats.backend_ip = backend.address_bytes.v4_address;
                    backend_found = true;
                    break;
                }
            }

            if (!backend_found) {
                // Backend not found for this entry. Skip and move to next entry.
                continue;
            }
            print_connection_entry(&stats);
        }
    }

    _print_trailer();

Exit:
    if (keys != nullptr) {
        free(keys);
    }
    if (values != nullptr) {
        free(values);
    }

    return result;
}
