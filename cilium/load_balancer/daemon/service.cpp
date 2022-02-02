// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "daemon.h"
#include <map>
#include <mutex>
#include <random>
#include "map.h"
#include "murmur3.h"
#include "util.h"
#include "maglev.h"

#define HASH_SIZE 19 // net.IPv6len + lenProto (0) + lenScope (1) + lenPort (2)
static std::mutex _service_map_mutex;
static std::map<uint32_t, service_t*> _service_map;
static LONG backend_id = 0;

static service_t*
_get_service_by_id(uint32_t service_id)
{
    std::map<uint32_t, service_t*>::iterator it;
    it = _service_map.find(service_id);
    if (it == _service_map.end()) {
        return nullptr;
    }
    return it->second;
}

static void
_delete_service_from_map(uint32_t service_id)
{
    _service_map.erase(service_id);
}

uint32_t
add_backend_to_map(backend_t* backend)
{
    UNREFERENCED_PARAMETER(backend);
    return 0;
}

// [IPv4 / IPv6]:Port
uint32_t
_compute_name_for_backend(backend_t* backend)
{
    try {
        char name[50] = {0};

        sprintf_s(name, 50, "[%s]:%u", backend->address_string.c_str(), backend->port);

        backend->name = std::string(name);
    } catch (...) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    return ERROR_SUCCESS;
}

void
get_permutation(_In_ std::vector<std::string>& backend_names)
{
    UNREFERENCED_PARAMETER(backend_names);
    return;
}

static uint32_t
_upsert_service(_In_ service_t* service)
{
    printf("Configuring maglev lookup table ... \n");
    uint32_t result = upsert_maglev_lookup_table(service);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

    result = update_service_endpoints(service);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

    result = update_reverse_nat(service);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

    printf("Configuring service endpoints ... \n");
    result = update_master_service(service);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

Exit:
    return result;
}

// Reverse of _upsert_service()
static uint32_t
_remove_service(service_t* service)
{
    uint32_t result = remove_master_service(service);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

    result = remove_reverse_nat(service);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

    result = delete_service_endpoints(service);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

    result = delete_maglev_lookup_table(service);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

Exit:
    return result;
}

static uint32_t
_populate_service_from_params(_Inout_ service_t* service, _In_ const service_params_t* params)
{
    service->id = params->id;
    service->frontend.address_string = std::string(params->frontend_ip);
    service->frontend.port = params->frontend_port;
    for (auto& backend : params->backends) {
        backend_t backend_node;
        backend_node.address_string = std::string(backend.backend_ip);
        backend_node.port = backend.backend_port;
        service->backends.emplace_back(backend_node);
    }

    return ERROR_SUCCESS;
}

static uint32_t
_delete_service(uint32_t service_id)
{
    bool any_step_failed = false;
    service_t* service = _get_service_by_id(service_id);
    if (service == nullptr) {
        return ERROR_NOT_FOUND;
    }

    // Remove service from service map.
    uint32_t result = _remove_service(service);
    if (result != ERROR_SUCCESS) {
        any_step_failed = true;
        printf("Failed to remove service endpoints. Error=%d\n", result);
        goto Exit;
    }

    // Remove backend nodes from the backend map.
    for (auto& backend : service->backends) {
        result = remove_backend_node_from_backend_map(&backend);
        if (result != ERROR_SUCCESS) {
            printf("Failed to remove backend node from map. Error=%d\n", result);
            goto Exit;
        }
    }

    // Cleanup neighbor entries for backends.
    for (auto& backend : service->backends) {
        result = delete_neighbor_entry(backend.family, &backend.address_bytes);
        if (result != ERROR_SUCCESS) {
            printf("Failed to delete neighbor entry for backend %d, error=%d\n", backend.id, result);
            goto Exit;
        }
    }

    // Delete the service entry from the map.
    _delete_service_from_map(service_id);
    service = nullptr;

Exit:
    return result;
}

uint32_t
delete_service(uint32_t service_id)
{
    return _delete_service(service_id);
}

static uint32_t
_program_service_to_xdp_maps(_In_ service_t* service)
{
    uint32_t result = ERROR_SUCCESS;

    // Get neighbor entries for each backend and update in the map.
    for (auto& backend : service->backends) {
        result = get_next_hop_mac_address(backend.family, &backend.address_bytes, &backend.next_hop_mac_address);
        if (result != ERROR_SUCCESS) {
            printf("backend %s is not reachable.\n", backend.address_string.c_str());
            goto Exit;
        }

        result = update_neighbor_entry(backend.family, &backend.address_bytes, &backend.next_hop_mac_address);
        if (result != ERROR_SUCCESS) {
            goto Exit;
        }
    }

    printf("Updating backend nodes to backend map ... \n");
    // Add backend nodes to backend map.
    for (auto& backend : service->backends) {
        result = add_backend_node_to_backend_map(&backend);
        if (result != 0) {
            goto Exit;
        }
    }

    // Add service to service map
    result = _upsert_service(service);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

Exit:
    return result;
}

uint32_t
program_services_to_xdp_maps()
{
    uint32_t result = ERROR_SUCCESS;
    for (auto& service_pair : _service_map) {
        result = _program_service_to_xdp_maps(service_pair.second);
        if (result != ERROR_SUCCESS) {
            printf("Failed to program service with id %d, error %d\n", service_pair.first, result);
            return result;
        }
    }

    return result;
}

uint32_t
add_or_update_service(_In_ service_params_t* service_params)
{
    // 0. Validations:
    //      1. service id is non-zero
    //      2. Minimum 1 backend is configured.
    // 1. Add the service to the global map.
    // 2. Calculate hash of each backend.
    // 3.
    uint32_t result = ERROR_SUCCESS;
    service_t* service = nullptr;

    // Validation.
    if (service_params->id == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    // See if the service id already exists.
    service = _get_service_by_id(service_params->id);
    if (service != nullptr) {
        // A service with same id exists. Delete the existing service.
        printf("Deleting older service configuration ...\n");
        delete_service(service_params->id);
        service = nullptr;
    }

    service = new service_t();
    if (service == nullptr) {
        printf("Unable to allocate memory for service.\n");
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    // Populate service from the params.
    result = _populate_service_from_params(service, service_params);
    if (result != ERROR_SUCCESS) {
        printf("Unable to parse command.\n");
        goto Exit;
    }

    // Convert frontend and backend IP strings to bytes.
    result = string_to_address(
        service->frontend.address_string, &service->frontend.address_bytes, &service->frontend.family);
    if (result != ERROR_SUCCESS) {
        result = ERROR_INVALID_PARAMETER;
        goto Exit;
    }

    for (auto& backend : service->backends) {
        result = string_to_address(backend.address_string, &backend.address_bytes, &backend.family);
        if (result != ERROR_SUCCESS) {
            result = ERROR_INVALID_PARAMETER;
            goto Exit;
        }

        // Compute "name" for each backend. The name looks like:
        // [IPv4/IPv6]:Port. This name is used by Maglev to sort the
        // backends.
        result = _compute_name_for_backend(&backend);
        if (result != ERROR_SUCCESS) {
            goto Exit;
        }
    }

    // Address family for both frontend and backend should be same.
    for (auto& backend : service->backends) {
        if (service->frontend.family != backend.family) {
            result = ERROR_INVALID_PARAMETER;
            goto Exit;
        }
    }

    // Generate unique ID for each backend.
    for (auto& backend : service->backends) {
        backend.id = (uint16_t)InterlockedIncrement(&backend_id);
    }

    result = _program_service_to_xdp_maps(service);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

    // Add service in the global map.
    _service_map[service->id] = service;

Exit:
    if (result != ERROR_SUCCESS) {
        if (service != nullptr) {
            delete service;
        }
    }
    return result;
}

void
dump_service_state(uint32_t service_id)
{
    service_t* service = _get_service_by_id(service_id);
    if (service == nullptr) {
        printf("Service with id %d not found\n", service_id);
        return;
    }
    print_ipv4_connection_track_entries(service);
}
