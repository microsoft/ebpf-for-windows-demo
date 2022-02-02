#include "lib/utils.h"

#define NAT46_PREFIX                                                                                 \
    {                                                                                                \
        .addr = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0 } \
    }
#define CT_MAP_TCP4 cilium_ct4_global
#define CT_MAP_ANY4 cilium_ct_any4_global
#define CT_MAP_TCP6 cilium_ct6_global
#define CT_MAP_ANY6 cilium_ct_any6_global
#define CT_MAP_SIZE_TCP 524288
#define CT_MAP_SIZE_ANY 262144
#define ALLOW_ICMP_FRAG_NEEDED 1
#define CAPTURE4_RULES cilium_capture4_rules
#define CAPTURE4_SIZE 16384
#define CAPTURE6_RULES cilium_capture6_rules
#define CAPTURE6_SIZE 16384
#define CILIUM_IPV4_FRAG_MAP_MAX_ENTRIES 8192
#define CILIUM_LB_MAP_MAX_ENTRIES 65536
#define CT_CLOSE_TIMEOUT 10
#define CT_CONNECTION_LIFETIME_NONTCP 60
#define CT_CONNECTION_LIFETIME_TCP 21600
#define CT_REPORT_FLAGS 0x0007
#define CT_REPORT_INTERVAL 5
#define CT_SERVICE_LIFETIME_NONTCP 60
#define CT_SERVICE_LIFETIME_TCP 21600
#define CT_SYN_TIMEOUT 60
// #define DIRECT_ROUTING_DEV_IFINDEX 2
#define DSR_ENCAP_IPIP 2

#define DSR_ENCAP_NONE 1
#define DSR_XLATE_BACKEND 2
#define DSR_XLATE_FRONTEND 1

#define EGRESS_MAP cilium_egress_v4
#define EGRESS_MAP_SIZE 16384
#define ENABLE_CAPTURE 1

#define ENABLE_EXTERNAL_IP 1
#define ENABLE_FIB_LOOKUP_BYPASS 1

#define ENABLE_HOST_SERVICES_FULL 1
#define ENABLE_HOST_SERVICES_PEER 1
#define ENABLE_HOST_SERVICES_TCP 1
#define ENABLE_HOST_SERVICES_UDP 1
#define ENABLE_IDENTITY_MARK 1
#define ENABLE_IPV4 1
#define ENABLE_IPV4_FRAGMENTS 1
#define ENABLE_IPV6 1
#define ENABLE_JIFFIES 1
#define ENABLE_LOADBALANCER 1
#define ENABLE_NODEPORT 1
#define ENABLE_NODEPORT_ACCELERATION 1
#define ENABLE_NODEPORT_HAIRPIN 1
#define ENABLE_REDIRECT_FAST 1
// EBPF_FOR_WINDOWS: Per discussion with Daniel, source
// range check is not needed for L4LB. Setting this to 0
// #define ENABLE_SRC_RANGE_CHECK 1
#define ENABLE_SRC_RANGE_CHECK 0
#define ENCRYPT_MAP cilium_encrypt_state
#define ENDPOINTS_MAP cilium_lxc
#define ENDPOINTS_MAP_SIZE 65535
#define EP_POLICY_MAP cilium_ep_to_policy
#define EVENTS_MAP cilium_events
#define HASH_INIT4_SEED 1910299206
#define HASH_INIT6_SEED 2454738568
#define HEALTH_ID 4
#define HOST_ID 1
#define INIT_ID 5
#define IPCACHE_MAP cilium_ipcache
#define IPCACHE_MAP_SIZE 512000
// #define IPV4_DIRECT_ROUTING 3245270794
#define IPV4_FRAG_DATAGRAMS_MAP cilium_ipv4_frag_datagrams
// #define IPV4_GATEWAY 0x4013c10a
// #define IPV4_LOOPBACK 0x12afea9
#define IPV4_MASK 0xffff
#define IPV4_RSS_PREFIX IPV4_DIRECT_ROUTING
#define IPV4_RSS_PREFIX_BITS 32
#define IPV6_RSS_PREFIX IPV6_DIRECT_ROUTING
#define IPV6_RSS_PREFIX_BITS 128
#define IS_L3_DEV(ifindex) false
#define KERNEL_HZ 250
#define LB4_BACKEND_MAP_V2 cilium_lb4_backends

#define LB4_MAGLEV_MAP_INNER cilium_lb4_maglev_inner
#define LB4_MAGLEV_MAP_OUTER cilium_lb4_maglev
#define LB4_REVERSE_NAT_MAP cilium_lb4_reverse_nat
#define LB4_REVERSE_NAT_SK_MAP cilium_lb4_reverse_sk
#define LB4_REVERSE_NAT_SK_MAP_SIZE 262144
#define LB4_SERVICES_MAP_V2 cilium_lb4_services_v2
#define LB4_SRC_RANGE_MAP cilium_lb4_source_range
#define LB4_SRC_RANGE_MAP_SIZE 65536
#define LB6_BACKEND_MAP_V2 cilium_lb6_backends

#define LB6_MAGLEV_MAP_INNER cilium_lb6_maglev_inner
#define LB6_MAGLEV_MAP_OUTER cilium_lb6_maglev
#define LB6_REVERSE_NAT_MAP cilium_lb6_reverse_nat
#define LB6_REVERSE_NAT_SK_MAP cilium_lb6_reverse_sk
#define LB6_REVERSE_NAT_SK_MAP_SIZE 262144
#define LB6_SERVICES_MAP_V2 cilium_lb6_services_v2
#define LB6_SRC_RANGE_MAP cilium_lb6_source_range
#define LB6_SRC_RANGE_MAP_SIZE 65536
#define LB_MAGLEV_LUT_SIZE 2039
#define LB_SELECTION 2
#define LB_SELECTION_MAGLEV 2
#define LB_SELECTION_RANDOM 1
// #define LOCAL_NODE_ID 6
#define METRICS_MAP cilium_metrics
#define METRICS_MAP_SIZE 1024
#define NODEPORT_NEIGH4 cilium_nodeport_neigh4
#define NODEPORT_NEIGH4_SIZE 524288
#define NODEPORT_NEIGH6 cilium_nodeport_neigh6
#define NODEPORT_NEIGH6_SIZE 524288
#define NODEPORT_PORT_MAX 32767
#define NODEPORT_PORT_MAX_NAT 65535
#define NODEPORT_PORT_MIN 30000
#define NODEPORT_PORT_MIN_NAT 32768
#define NO_REDIRECT 1
#define POLICY_CALL_MAP cilium_call_policy
#define POLICY_MAP_SIZE 16384
#define POLICY_PROG_MAP_SIZE 65535
#define PREALLOCATE_MAPS 1
// #define REMOTE_NODE_ID 6
#define SIGNAL_MAP cilium_signals
#define SNAT_MAPPING_IPV4 cilium_snat_v4_external
#define SNAT_MAPPING_IPV4_SIZE 524288
#define SNAT_MAPPING_IPV6 cilium_snat_v6_external
#define SNAT_MAPPING_IPV6_SIZE 524288
#define SOCKOPS_MAP_SIZE 65535
#define TRACE_PAYLOAD_LEN 128ULL
#define TUNNEL_ENDPOINT_MAP_SIZE 65536
#define TUNNEL_MAP cilium_tunnel_map
// #define UNMANAGED_ID 3
#define VLAN_FILTER(ifindex, vlan_id) return false
// #define WORLD_ID 2
