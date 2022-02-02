// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "daemon.h"
#include <map>
#include <random>
#include "map.h"
#include "murmur3.h"
#include "util.h"

static uint32_t _murmur_seed = 616034178;

uint32_t
ebpf_random_uint32()
{
    std::random_device rd;
    std::mt19937 mt(rd());
    return mt();
}

void
get_offset_and_skip(_In_ std::string& backend_name, uint64_t table_size, _Out_ uint64_t* offset, _Out_ uint64_t* skip)
{
    *offset = 0;
    *skip = 0;
    uint64_t array[2] = {0};

    MurmurHash3_x64_128(backend_name.c_str(), (int)strlen(backend_name.c_str()), _murmur_seed, array);

    *offset = array[0] % table_size;
    *skip = (array[1] % (table_size - 1)) + 1;
}

uint32_t
get_permutation(
    _In_ std::vector<std::string>& backend_names, uint64_t table_size, _Out_ std::vector<uint64_t>** permutation)
{
    int count = (int)backend_names.size();
    *permutation = new std::vector<uint64_t>(count * table_size);
    if (*permutation == nullptr) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    for (uint64_t i = 0; i < backend_names.size(); i++) {
        uint64_t offset;
        uint64_t skip;
        get_offset_and_skip(backend_names[i], table_size, &offset, &skip);
        (*permutation)->operator[](i* table_size) = offset % table_size;
        for (uint64_t j = 1; j < table_size; j++) {
            (*permutation)->operator[]((i * table_size) + j) =
                ((*permutation)->operator[]((i * table_size) + (j - 1)) + skip) % table_size;
        }
    }
    return ERROR_SUCCESS;
}

void
get_lookup_table(
    _In_ std::vector<std::string>& backend_names, _Inout_ std::vector<int>& lookup_table, uint64_t table_size)
{
    uint32_t result;
    std::vector<uint64_t>* permutation;
    if (backend_names.size() == 0) {
        return;
    }

    result = get_permutation(backend_names, table_size, &permutation);
    if (result != ERROR_SUCCESS) {
        return;
    }

    std::vector<uint32_t> next(backend_names.size(), 0);

    for (int j = 0; j < table_size; j++) {
        lookup_table[j] = -1;
    }

    int length = (int)backend_names.size();

    for (uint64_t n = 0; n < table_size; n++) {
        int i = n % length;
        auto c = permutation->operator[]((i * table_size) + next[i]);
        while (lookup_table[c] >= 0) {
            next[i] += 1;
            c = permutation->operator[]((i * table_size) + next[i]);
        }

        lookup_table[c] = i;
        next[i] += 1;
    }

    delete (permutation);
}

uint32_t
delete_maglev_lookup_table(service_t* service)
{
    bool ipv6 = service->frontend.family == AF_INET ? FALSE : TRUE;
    return delete_maglev_table_from_map(ipv6, (uint16_t)service->id);
}

uint32_t
upsert_maglev_lookup_table(service_t* service)
{
    uint32_t result;
    // Create a map with backend "names"
    std::vector<std::string> backend_names;
    std::vector<int> lookup_table;
    for (auto& backend : service->backends) {
        backend_names.push_back(backend.name);
    }

    lookup_table.resize(MAGLEV_TABLE_SIZE);
    get_lookup_table(backend_names, lookup_table, MAGLEV_TABLE_SIZE);

    std::vector<uint32_t>* maglev_backend_ids_buffer = new std::vector<uint32_t>(MAGLEV_TABLE_SIZE);
    if (maglev_backend_ids_buffer == nullptr) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    for (int i = 0; i < lookup_table.size(); i++) {
        maglev_backend_ids_buffer->operator[](i) = service->backends[lookup_table[i]].id;
    }

    bool ipv6 = service->frontend.family == AF_INET ? FALSE : TRUE;
    result = update_maglev_table_to_map(ipv6, (uint16_t)service->id, *maglev_backend_ids_buffer);

    delete (maglev_backend_ids_buffer);
    return result;
}
