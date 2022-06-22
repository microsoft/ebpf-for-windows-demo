// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

extern "C"
{
#include "ebpf_api.h"
#include "linux/bpf.h"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
}

uint32_t
initialize_map_entries();

fd_t
get_map_fd(const char* map_name);

std::string
get_map_pin_path(const char* map_name);

uint32_t
add_backend_node_to_backend_map(backend_t* backend_node);

uint32_t
update_maglev_table_to_map(bool ipv6, uint16_t rev_nat_id, std::vector<uint32_t>& backend_ids);

uint32_t
update_service_endpoints(service_t* service);

uint32_t
update_reverse_nat(service_t* service);

uint32_t
update_master_service(service_t* service);

uint32_t
update_neighbor_entry(
    ADDRESS_FAMILY family, _In_ const address_bytes_t* address, _In_ const mac_address_t* mac_address);

uint32_t
clean_old_pinned_maps();

uint32_t
get_total_program_count();

uint32_t
get_total_map_count();

uint32_t
remove_master_service(service_t* service);

uint32_t
remove_reverse_nat(service_t* service);

uint32_t
delete_service_endpoints(service_t* service);

uint32_t
delete_maglev_table_from_map(bool ipv6, uint16_t rev_nat_id);

uint32_t
remove_backend_node_from_backend_map(backend_t* backend_node);

uint32_t
delete_neighbor_entry(ADDRESS_FAMILY family, _In_ const address_bytes_t* address);

uint32_t
update_neighbor_map_for_destination(_In_ const char* destination_address);

uint32_t
print_ipv4_connection_track_entries(_In_ const service_t* service);