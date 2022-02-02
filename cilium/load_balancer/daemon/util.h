// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "daemon.h"
#include <map>
#include <locale>
#include <codecvt>

#include <iostream>
#include <fstream>

#include <winsock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>

#define MAXIMUM_IP_BUFFER_SIZE 65
#define LINK_LOCAL_PREFIX "fe80"

typedef enum foreground_color
{
    yellow,
    green
} foreground_color_t;

std::wstring
get_wstring_from_string(std::string text);

std::string
address_to_string(_In_ const void* sockaddr, ADDRESS_FAMILY family);

_Success_(return == ERROR_SUCCESS) uint32_t
    string_to_address(_In_ std::string& address_string, _Out_ address_bytes_t* address, _Out_ ADDRESS_FAMILY* family);

uint32_t
wsa_initialize();

_Success_(return == ERROR_SUCCESS) uint32_t get_next_hop_mac_address(
    ADDRESS_FAMILY family, _In_ address_bytes_t* address_bytes, _Out_ mac_address_t* mac_address);

DWORD
get_interface_properties(_Inout_ interface_info_t* info, bool v4_enabled, bool v6_enabled);

std::string
integer_to_v4_address_string(uint32_t address);

void
set_foreground_color(foreground_color_t color);

void
reset_foreground_color();

uint32_t
get_current_time_seconds_since_boot();