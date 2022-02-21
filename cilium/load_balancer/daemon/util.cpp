// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

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
#include "util.h"

#define MAX_TRIES 3
#define WORKING_BUFFER_SIZE 15000

HANDLE _console_handle = INVALID_HANDLE_VALUE;

std::wstring
get_wstring_from_string(std::string text)
{
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::wstring wide = converter.from_bytes(text);

    return wide;
}

uint32_t
wsa_initialize()
{
    WSADATA data = {0};
    return WSAStartup(2, &data);
}

std::string
address_to_string(_In_ const void* sockaddr, ADDRESS_FAMILY family)
{
    char ip_string[MAXIMUM_IP_BUFFER_SIZE] = {0};
    if (family == AF_INET) {
        struct sockaddr_in* addr = (struct sockaddr_in*)sockaddr;
        InetNtopA(AF_INET, &addr->sin_addr, ip_string, MAXIMUM_IP_BUFFER_SIZE);
        return std::string(ip_string);
    } else {
        struct sockaddr_in6* addr = (struct sockaddr_in6*)sockaddr;
        InetNtopA(AF_INET6, &addr->sin6_addr, ip_string, MAXIMUM_IP_BUFFER_SIZE);
        return std::string(ip_string);
    }
}

std::string
integer_to_v4_address_string(uint32_t address)
{
    char ip_string[MAXIMUM_IP_BUFFER_SIZE] = {0};
    InetNtopA(AF_INET, &address, ip_string, MAXIMUM_IP_BUFFER_SIZE);
    return std::string(ip_string);
}

_Success_(return == ERROR_SUCCESS) uint32_t
    string_to_address(_In_ std::string& address_string, _Out_ address_bytes_t* address, _Out_ ADDRESS_FAMILY* family)
{
    uint32_t result;
    SOCKADDR_STORAGE storage;
    int size = sizeof(storage);
    *family = AF_UNSPEC;

    // First try IPv4
    memset(&storage, 0, sizeof(storage));
    ((sockaddr_in*)&storage)->sin_family = AF_INET;
    result = WSAStringToAddressA((LPSTR)address_string.c_str(), AF_INET, nullptr, (SOCKADDR*)&storage, &size);
    if (result == ERROR_SUCCESS) {
        // We found an IPv4 address.
        *family = AF_INET;
        address->v4_address = ((sockaddr_in*)&storage)->sin_addr.S_un.S_addr;
        return result;
    }

    // Next try IPv6.
    memset(&storage, 0, sizeof(SOCKADDR_STORAGE));
    ((sockaddr_in6*)&storage)->sin6_family = AF_INET6;
    result = WSAStringToAddressA((LPSTR)address_string.c_str(), AF_INET6, nullptr, (SOCKADDR*)&storage, &size);
    if (result == ERROR_SUCCESS) {
        *family = AF_INET6;
        memcpy(address->v6_address, ((sockaddr_in6*)&storage)->sin6_addr.u.Byte, IPV6_ADDRESS_LENGTH);
        return result;
    }

    return result;
}

/**
 * @brief Get the mac address of the next hop for the provided remote address.
 * @param[in] family Address family.
 * @param[in] address_bytes IP address for which to find the next hop address.
 * @param[out] physical_address The physical address.
 */
_Success_(return == ERROR_SUCCESS) uint32_t get_next_hop_mac_address(
    ADDRESS_FAMILY family, _In_ address_bytes_t* address_bytes, _Out_ mac_address_t* mac_address)
{
    uint32_t result;
    SOCKADDR_INET source = {0};
    SOCKADDR_INET destination;
    MIB_IPFORWARD_ROW2 route;
    SOCKADDR_INET* nextHop = nullptr;
    MIB_IPNET_ROW2 neighbor = {0};

    *mac_address = {0};

    // 1. Call GetBestRoute2 to get the route entry.
    // 2. If NextHop in the route is 0, then the destination is onlink,
    //    else we have a next hop.
    // 3. Call ResolveIpNetEntry2() for the next hop (calculated in step 2)

    destination.si_family = family;
    if (family == AF_INET) {
        destination.Ipv4.sin_addr.S_un.S_addr = address_bytes->v4_address;
    } else {
        memcpy(destination.Ipv6.sin6_addr.u.Byte, address_bytes->v6_address, IPV6_ADDRESS_LENGTH);
    }

    result = GetBestRoute2(nullptr, 0, nullptr, &destination, 0, &route, &source);
    if (result != ERROR_SUCCESS) {
        printf("No best route found. returning.\n");
        return result;
    }

    if (family == AF_INET) {
        if (route.NextHop.Ipv4.sin_addr.S_un.S_addr == 0) {
            // Destination is on-link.
            nextHop = &destination;
        } else {
            nextHop = &route.NextHop;
        }
    } else {
        char address[IPV6_ADDRESS_LENGTH] = {0};
        if (memcmp(route.NextHop.Ipv6.sin6_addr.u.Byte, address, IPV6_ADDRESS_LENGTH) == 0) {
            // Destination is on-link.
            nextHop = &destination;
            printf("IPv6: destination is on-link\n");
        } else {
            nextHop = &route.NextHop;
            printf("IPv6: destination is NOT on-link\n");
        }
    }

    neighbor.Address = *nextHop;
    result = ResolveIpNetEntry2(&neighbor, nullptr);
    if (result != ERROR_SUCCESS) {
        printf("ResolveIpNetEntry2 failed.\n");
        return result;
    }
    if (neighbor.PhysicalAddressLength != MAC_ADDRESS_LENGTH) {
        return ERROR_INVALID_PARAMETER;
    }
    memcpy(mac_address->addr, neighbor.PhysicalAddress, MAC_ADDRESS_LENGTH);

    return result;
}

DWORD
get_interface_properties(_Inout_ interface_info_t* info, bool v4_enabled, bool v6_enabled)
{
    DWORD error = 0;
    // Set the flags to pass to GetAdaptersAddresses
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    // default to unspecified address family (both)
    ULONG family = AF_UNSPEC;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG outBufLen = 0;
    ULONG Iterations = 0;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
    bool found = false;
    char ip_string[MAXIMUM_IP_BUFFER_SIZE];

    if (info == nullptr || info->name.c_str() == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }

    // Allocate a 15 KB buffer to start with.
    outBufLen = WORKING_BUFFER_SIZE;

    do {
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        if (pAddresses == NULL) {
            printf("Memory allocation failed for IP_ADAPTER_ADDRESSES struct\n");
            exit(1);
        }

        error = GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);
        if (error == ERROR_BUFFER_OVERFLOW) {
            free(pAddresses);
            pAddresses = NULL;
        } else {
            break;
        }

        Iterations++;

    } while ((error == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));

    if (error == NO_ERROR) {
        // If successful, output some information from the data we received
        pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            // TODO: Do a case insensitive string comparison.
            if (_wcsicmp(pCurrAddresses->FriendlyName, info->name.c_str()) == 0) {
                found = true;

                // Fill the required information.
                info->ifIndex = pCurrAddresses->IfIndex;
                info->mtu = pCurrAddresses->Mtu;
                memcpy(info->mac_address, pCurrAddresses->PhysicalAddress, MAX_ADAPTER_ADDRESS_LENGTH);
                // Get the first unicast address for both ipv4 and ipv6
                pUnicast = pCurrAddresses->FirstUnicastAddress;
                bool v4_found = !v4_enabled ? true : false;
                bool v6_found = !v6_enabled ? true : false;
                while (pUnicast != nullptr) {
                    if (v4_enabled && pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                        info->ipv4_address = *((SOCKADDR_IN*)pUnicast->Address.lpSockaddr);
                        v4_found = true;
                    } else if (v6_enabled && pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
                        // Skip if this is link-local address.
                        ZeroMemory(ip_string, MAXIMUM_IP_BUFFER_SIZE);
                        InetNtopA(
                            AF_INET6,
                            &((SOCKADDR_IN6*)pUnicast->Address.lpSockaddr)->sin6_addr,
                            ip_string,
                            MAXIMUM_IP_BUFFER_SIZE);
                        if (strstr(ip_string, LINK_LOCAL_PREFIX) == ip_string) {
                            pUnicast = pUnicast->Next;
                            continue;
                        }
                        info->ipv6_address = *((SOCKADDR_IN6*)pUnicast->Address.lpSockaddr);
                        v6_found = true;
                    }
                    if (v4_found && v6_found) {
                        break;
                    }
                    pUnicast = pUnicast->Next;
                }
                if (!v4_found || !v6_found) {
                    found = false;
                }
                break;
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
    }

    if (!found) {
        error = ERROR_NOT_FOUND;
    }

    if (pAddresses) {
        free(pAddresses);
    }

    return error;
}

void
set_foreground_color(foreground_color_t color)
{
    if (_console_handle == INVALID_HANDLE_VALUE) {
        _console_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    }
    uint16_t color_mask = 0;
    switch (color) {
    case foreground_color_t::green:
        color_mask = FOREGROUND_GREEN;
        break;
    case foreground_color_t::yellow:
        color_mask = FOREGROUND_GREEN | FOREGROUND_RED;
        break;
    }
    SetConsoleTextAttribute(_console_handle, color_mask);
}

void
reset_foreground_color()
{
    if (_console_handle == INVALID_HANDLE_VALUE) {
        _console_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    }
    SetConsoleTextAttribute(_console_handle, 7);
}

uint32_t
get_current_time_seconds_since_boot()
{
    uint64_t interrupt_time;
    QueryInterruptTimePrecise(&interrupt_time);

    return static_cast<uint32_t>(interrupt_time / 10000000);
}
