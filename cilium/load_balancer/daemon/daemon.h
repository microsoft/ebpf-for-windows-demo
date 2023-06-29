// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <string>
#include <vector>
#include <winsock2.h>
#include <WS2tcpip.h>

// TODO: This is added here just for compilation to work.
// This typedef is defined in api_internal.h, which is wrong. It should
// be defined in some public header file.
typedef int (*ring_buffer_sample_fn)(void* ctx, void* data, size_t size);

#define MAX_ADAPTER_ADDRESS_LENGTH 8
#define MAGLEV_TABLE_SIZE 2039

#define MAC_ADDRESS_LENGTH 6
#define IPV6_ADDRESS_LENGTH 16

typedef enum protocol
{
    any = 0,
    tcp = 6,
    udp = 17
} protocol_t;

typedef union address_bytes
{
    // Big endian.
    uint32_t v4_address{};
    uint8_t v6_address[IPV6_ADDRESS_LENGTH];
} address_bytes_t;

typedef union mac_address
{
    struct
    {
        uint32_t p1;
        uint16_t p2;
    } addr_struct;
    uint8_t addr[6];
} mac_address_t;

typedef struct backend
{
    ADDRESS_FAMILY family{};
    std::string address_string;
    address_bytes_t address_bytes;
    uint16_t port{};
    uint32_t id{};
    std::string name;
    mac_address_t next_hop_mac_address{};
} backend_t;

typedef struct frontend
{
    ADDRESS_FAMILY family{};
    std::string address_string;
    address_bytes_t address_bytes;
    uint16_t port{};
    protocol_t protocol{};
} frontend_t;

typedef struct service
{
    uint32_t id{};
    frontend_t frontend;
    std::vector<backend_t> backends;
} service_t;

typedef struct backend_params
{
    std::string backend_ip;
    uint16_t backend_port{};
} backend_params_t;

typedef enum service_operation
{
    Update,
    Delete,
    DumpState
} service_operation_t;

typedef struct service_params
{
    service_operation_t operation{};
    uint32_t id{};
    std::string frontend_ip;
    uint16_t frontend_port{};
    std::vector<backend_params_t> backends;
} service_params_t;

typedef struct interface_info
{
    std::wstring name;
    SOCKADDR_IN ipv4_address = {0};
    SOCKADDR_IN6 ipv6_address = {0};
    uint32_t mtu = 0;
    uint32_t ifIndex = 0;
    uint8_t mac_address[MAX_ADAPTER_ADDRESS_LENGTH]{};
} interface_info_t;

typedef enum lb_mode
{
    LB_MODE_INVALID,
    LB_MODE_DSR,
    LB_MODE_SNAT
} lb_mode_t;

typedef struct global_config
{
    interface_info_t info{};
    lb_mode_t mode{};
    bool v4_enabled{};
    bool v6_enabled{};
} global_config_t;
