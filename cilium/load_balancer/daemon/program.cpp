// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This file contains code to compile the ebpf program based on the input params.

#include "daemon.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
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
extern "C"
{
#include "ebpf_api.h"
}
#include <io.h>
#include "map.h"

#define FILE_PATH ".\\bpf\\"
#define NODE_CONFIG_PREFIX "node_config"
#define XDP_PROGRAM_PIN_PATH "/ebpf/global/cilium_xdp_program"
#define XDP_ENTRY_PROGRAM_NAME "bpf_xdp_entry"

using namespace std;
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define DEFAULT_INTERFACE_INFO_COUNT 10

#define CILIUM_CALL_DROP_NOTIFY 1
#define CILIUM_CALL_ERROR_NOTIFY 2
#define CILIUM_CALL_SEND_ICMP6_ECHO_REPLY 3
#define CILIUM_CALL_HANDLE_ICMP6_NS 4
#define CILIUM_CALL_SEND_ICMP6_TIME_EXCEEDED 5
#define CILIUM_CALL_ARP 6
#define CILIUM_CALL_IPV4_FROM_LXC 7
#define CILIUM_CALL_NAT64 8
#define CILIUM_CALL_NAT46 9
#define CILIUM_CALL_IPV6_FROM_LXC 10
#define CILIUM_CALL_IPV4_TO_LXC_POLICY_ONLY 11
#define CILIUM_CALL_IPV4_TO_HOST_POLICY_ONLY CILIUM_CALL_IPV4_TO_LXC_POLICY_ONLY
#define CILIUM_CALL_IPV6_TO_LXC_POLICY_ONLY 12
#define CILIUM_CALL_IPV6_TO_HOST_POLICY_ONLY CILIUM_CALL_IPV6_TO_LXC_POLICY_ONLY
#define CILIUM_CALL_IPV4_TO_ENDPOINT 13
#define CILIUM_CALL_IPV6_TO_ENDPOINT 14
#define CILIUM_CALL_IPV4_NODEPORT_NAT 15
#define CILIUM_CALL_IPV6_NODEPORT_NAT 16
#define CILIUM_CALL_IPV4_NODEPORT_REVNAT 17
#define CILIUM_CALL_IPV6_NODEPORT_REVNAT 18
#define CILIUM_CALL_IPV4_ENCAP_NODEPORT_NAT 19
#define CILIUM_CALL_IPV4_NODEPORT_DSR 20
#define CILIUM_CALL_IPV6_NODEPORT_DSR 21
#define CILIUM_CALL_IPV4_FROM_HOST 22
#define CILIUM_CALL_IPV6_FROM_HOST 23
#define CILIUM_CALL_IPV6_ENCAP_NODEPORT_NAT 24
#define CILIUM_CALL_SIZE 25

#define CILIUM_TAIL_CALL_MAP "cilium_calls_xdp"

#define CILIUM_CALL_IPV4_NODEPORT_DSR_NAME "tail_nodeport_ipv4_dsr"
#define CILIUM_CALL_IPV4_NODEPORT_NAT_NAME "tail_nodeport_nat_ipv4"
#define CILIUM_CALL_IPV4_NODEPORT_REVNAT_NAME "tail_rev_nodeport_lb4"
#define CILIUM_CALL_IPV4_ENCAP_NODEPORT_NAT_NAME "tail_handle_nat_fwd_ipv4"
#define CILIUM_CALL_IPV4_FROM_LXC_NAME "tail_lb_ipv4"

#define CILIUM_CALL_IPV6_NODEPORT_DSR_NAME "tail_nodeport_ipv6_dsr"
#define CILIUM_CALL_IPV6_NODEPORT_NAT_NAME "tail_nodeport_nat_ipv6"
#define CILIUM_CALL_IPV6_NODEPORT_REVNAT_NAME "tail_rev_nodeport_lb6"
#define CILIUM_CALL_IPV6_ENCAP_NODEPORT_NAT_NAME "tail_handle_nat_fwd_ipv6"
#define CILIUM_CALL_IPV6_FROM_LXC_NAME "tail_lb_ipv6"

#define CILIUM_CALL_DROP_NOTIFY_NAME "__send_drop_notify"

#define XDP_ENTRY_PROGRAM "bpf_xdp_entry"

typedef struct program_name_to_map_index
{
    std::string program_name;
    uint32_t index;
} program_name_to_map_index_t;

program_name_to_map_index_t cilium_tail_call_maps[] = {
    {std::string(CILIUM_CALL_IPV4_NODEPORT_DSR_NAME), CILIUM_CALL_IPV4_NODEPORT_DSR},
    {std::string(CILIUM_CALL_IPV4_NODEPORT_NAT_NAME), CILIUM_CALL_IPV4_NODEPORT_NAT},
    {std::string(CILIUM_CALL_IPV4_NODEPORT_REVNAT_NAME), CILIUM_CALL_IPV4_NODEPORT_REVNAT},
    {std::string(CILIUM_CALL_IPV4_ENCAP_NODEPORT_NAT_NAME), CILIUM_CALL_IPV4_ENCAP_NODEPORT_NAT},
    {std::string(CILIUM_CALL_IPV4_FROM_LXC_NAME), CILIUM_CALL_IPV4_FROM_LXC},

    {std::string(CILIUM_CALL_IPV6_NODEPORT_DSR_NAME), CILIUM_CALL_IPV6_NODEPORT_DSR},
    {std::string(CILIUM_CALL_IPV6_NODEPORT_NAT_NAME), CILIUM_CALL_IPV6_NODEPORT_NAT},
    {std::string(CILIUM_CALL_IPV6_NODEPORT_REVNAT_NAME), CILIUM_CALL_IPV6_NODEPORT_REVNAT},
    {std::string(CILIUM_CALL_IPV6_ENCAP_NODEPORT_NAT_NAME), CILIUM_CALL_IPV6_ENCAP_NODEPORT_NAT},
    {std::string(CILIUM_CALL_IPV6_FROM_LXC_NAME), CILIUM_CALL_IPV6_FROM_LXC},

    {std::string(CILIUM_CALL_DROP_NOTIFY_NAME), CILIUM_CALL_DROP_NOTIFY},
};

std::map<std::string, std::string> _compile_time_defines;

string
format_mac_address(const uint8_t* mac_address)
{
    char format[50] = {0};
    sprintf_s(
        format,
        50,
        "{0x%x,0x%x,0x%x,0x%x,0x%x,0x%x}",
        mac_address[0],
        mac_address[1],
        mac_address[2],
        mac_address[3],
        mac_address[4],
        mac_address[5]);

    return std::string(format);
}

static string
_format_ipv6_address(_In_ const SOCKADDR_IN6* ipv6_address)
{
    char format[200] = {0};
    const UCHAR* address_bytes = ipv6_address->sin6_addr.u.Byte;
    sprintf_s(
        format,
        200,
        "0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x",
        address_bytes[0],
        address_bytes[1],
        address_bytes[2],
        address_bytes[3],
        address_bytes[4],
        address_bytes[5],
        address_bytes[6],
        address_bytes[7],
        address_bytes[8],
        address_bytes[9],
        address_bytes[10],
        address_bytes[11],
        address_bytes[12],
        address_bytes[13],
        address_bytes[14],
        address_bytes[15]);

    return std::string(format);
}

static string
_get_router_ip_macro(_In_ const interface_info_t* info)
{
    std::string macro = "DEFINE_IPV6(ROUTER_IP, ";
    macro += _format_ipv6_address(&info->ipv6_address).c_str();
    macro += ");";

    return macro;
}

static string
_get_ipv6_direct_routing_macro(_In_ const interface_info_t* info)
{
    std::string macro = "{ .addr = {";
    macro += _format_ipv6_address(&info->ipv6_address).c_str();
    macro += "} }";

    return macro;
}

string
_get_mac_address_by_ifindex_macro(_In_ const interface_info_t* info)
{
    std::string macro =
        "({ \\\nunion macaddr __mac = {.addr = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}; \\\nswitch (IFINDEX) { \\\n";

    macro += "case ";
    macro += std::to_string(info->ifIndex);
    macro += ": {union macaddr __tmp = {.addr = ";
    macro += format_mac_address(info->mac_address).c_str();
    macro += "}; __mac=__tmp;} break; \\\n} \\\n__mac; })";

    return macro;
}

static uint32_t
_populate_compile_time_defines(_In_ lb_mode_t mode, _In_ const interface_info_t* info)
{
    uint32_t result = ERROR_SUCCESS;
    try {
        _compile_time_defines.clear();

        // Common values
        _compile_time_defines["MTU"] = std::to_string(info->mtu);
        string mac_address_macro = _get_mac_address_by_ifindex_macro(info);
        _compile_time_defines["NATIVE_DEV_MAC_BY_IFINDEX(IFINDEX)"] = mac_address_macro;
        _compile_time_defines["IPV6_DIRECT_ROUTING"] = _get_ipv6_direct_routing_macro(info);
        // IPv4 address should be in big-endian.
        // "info->ipv4_address.sin_addr.S_un.S_addr" is already big endian.
        string ipv4_address = to_string(info->ipv4_address.sin_addr.S_un.S_addr);
        _compile_time_defines["IPV4_DIRECT_ROUTING"] = ipv4_address;
        _compile_time_defines["DIRECT_ROUTING_DEV_IFINDEX"] = to_string(info->ifIndex);

        if (mode == LB_MODE_DSR) {
            _compile_time_defines["DSR_ENCAP_MODE"] = "2";
            _compile_time_defines["DSR_XLATE_MODE"] = "1";
            _compile_time_defines["ENABLE_DSR"] = "1";

            _compile_time_defines["ENABLE_HEALTH_CHECK"] = "1";
            _compile_time_defines["LB4_HEALTH_MAP"] = "cilium_lb4_health";
            _compile_time_defines["LB6_HEALTH_MAP"] = "cilium_lb6_health";
        } else {
            _compile_time_defines["DSR_ENCAP_MODE"] = "0";
            _compile_time_defines["DSR_XLATE_MODE"] = "0";
        }
    } catch (...) {
        result = ERROR_NOT_ENOUGH_MEMORY;
    }

    return result;
}

uint32_t
_generate_header_files(_In_ lb_mode_t mode, _In_ const interface_info_t* info)
{
    uint32_t result;
    string file_name;
    ofstream file;

    result = _populate_compile_time_defines(mode, info);
    if (result != ERROR_SUCCESS) {
        return result;
    }

    file_name = FILE_PATH;
    file_name += NODE_CONFIG_PREFIX;
    if (mode == LB_MODE_DSR) {
        file_name += "_dsr.h";
    } else {
        file_name += "_snat.h";
    }

    std::ofstream of(file_name);
    if (!of.is_open()) {
        result = GetLastError();
        printf("failed of open file. Error=%d\n", result);
        goto Exit;
    }

    // Add header.
    of << "// THIS IS A GENERATED FILE !\n\n";

    // Special case handling.
    of << _get_router_ip_macro(info) << std::endl;

    // Add the macros.
    for (auto const& macro : _compile_time_defines) {
        of << "#define " << macro.first << " " << macro.second << std::endl;
    }

    of.flush();
    of.close();

Exit:
    return result;
}

std::string
_generate_compile_command(
    _In_ const interface_info_t* interface_info,
    _In_ const SYSTEM_INFO* system_info,
    lb_mode_t mode,
    bool track_code_flow)
{
    // clang -g -O2 -target bpf -mcpu=v1 -std=gnu89 -nostdinc -D__NR_CPUS__=10 -Wall -Wextra -Werror -Wshadow
    // -Wno-address-of-packed-member -Wno-unknown-warning-option -Wno-gnu-variable-sized-type-not-at-end
    // -Wdeclaration-after-statement -DSECLABEL=2 -DNODE_MAC={.addr={0x0,0x15,0x5d,0x6e,0x85,0x4}}
    // -DCALLS_MAP=cilium_calls_xdp -Dcapture_enabled=0 -DNATIVE_DEV_IFINDEX=2 -DDISABLE_LOOPBACK_LB -I.\include
    // -I. -I..\ -I..\..\include -I..\..\libs\platform\kernel -c bpf_xdp.c -o ..\object\bpf_xdp_dsr.o
    // -DEBPF_FOR_WINDOWS -DMODE_DSR

    // clang -g -O2 -target bpf -mcpu=v1 -std=gnu89 -nostdinc -D__NR_CPUS__=10 -Wall -Wextra -Werror -Wshadow
    // -Wno-address-of-packed-member -Wno-unknown-warning-option -Wno-gnu-variable-sized-type-not-at-end
    // -Wdeclaration-after-statement -DSECLABEL=2 -DNODE_MAC={.addr={0x0,0x15,0x5d,0x6e,0x85,0x4}}
    // -DCALLS_MAP=cilium_calls_xdp -Dcapture_enabled=0 -DNATIVE_DEV_IFINDEX=2 -DDISABLE_LOOPBACK_LB -I.\include
    // -I. -I..\ -I..\..\include -I..\..\libs\platform\kernel -c bpf_xdp.c -o ..\object\bpf_xdp_snat.o
    // -DEBPF_FOR_WINDOWS -DMODE_SNAT

    std::string command("clang");

    // Add constants.
    command += " -g -O2 -target bpf -mcpu=v1 -std=gnu89 -nostdinc -Wextra -Werror -Wshadow "
               "-Wno-address-of-packed-member -Wno-unknown-warning-option -Wno-gnu-variable-sized-type-not-at-end "
               "-Wdeclaration-after-statement -DSECLABEL=2 -Dcapture_enabled=0 -DDISABLE_LOOPBACK_LB "
               "-DCALLS_MAP=cilium_calls_xdp";
    // Add include paths.
    command += " -I.\\include -I. -I..\\ -I..\\include";
    // Add mode option.
    command += (mode == LB_MODE_DSR) ? " -DMODE_DSR" : " -DMODE_SNAT";
    command += " -DEBPF_FOR_WINDOWS";

    // Add variables.
    command += " -D__NR_CPUS__=" + to_string(system_info->dwNumberOfProcessors);
    command += " -DNODE_MAC={.addr=" + format_mac_address(interface_info->mac_address) + "}";
    command += " -DNATIVE_DEV_IFINDEX=" + to_string(interface_info->ifIndex);

    if (track_code_flow) {
        command += " -DTRACK_CODE_FLOW";
    }

    // Add the file names.
    command += " -c bpf_xdp.c";
    command += " -o ..\\bpf_xdp";
    command += (mode == LB_MODE_DSR) ? "_dsr.o" : "_snat.o";

    return command;
}

static uint32_t
_compile_xdp_program(_In_ const interface_info_t* info, lb_mode_t mode, bool track_code_flow)
{
    uint32_t result = ERROR_SUCCESS;
    std::string compile_command;

    printf("Compiling XDP eBPF program for %s ...\n", (mode == LB_MODE_DSR ? "DSR" : "SNAT"));

    result = _generate_header_files(mode, info);
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

    // Change working directory to ".\bpf"
    if (SetCurrentDirectory(L".\\bpf") == 0) {
        result = GetLastError();
        printf("Failed to change directory to bpf\n");
        goto Exit;
    }

    // Get the number of processors in the system.
    SYSTEM_INFO system_info;
    GetSystemInfo(&system_info);

    // Build the compile command.
    compile_command = _generate_compile_command(info, &system_info, mode, track_code_flow);

    if (system(compile_command.c_str()) != 0) {
        result = GetLastError();
        printf("Failed to compile the XDP program with error %d\n", result);
        goto Exit;
    }

Exit:
    // Change working directory back to ".\..\""
    if (SetCurrentDirectory(L".\\..") == 0) {
        printf("Failed to change directory to ..\\\n");
        goto Exit;
    }
    return result;
}

int
_get_map_index_from_program_name(const char* program_name)
{
    size_t array_size = sizeof(cilium_tail_call_maps) / sizeof(program_name_to_map_index_t);
    for (size_t i = 0; i < array_size; i++) {
        if (strncmp(cilium_tail_call_maps[i].program_name.c_str(), program_name, strlen(program_name)) == 0) {
            return cilium_tail_call_maps[i].index;
        }
    }

    return -1;
}

static uint32_t
_populate_tail_call_map(_In_ const struct bpf_object* object)
{
    uint32_t result = ERROR_SUCCESS;
    int index;

    // Get fd to tail calls map.
    struct bpf_map* call_map = bpf_object__find_map_by_name(object, CILIUM_TAIL_CALL_MAP);
    if (call_map == nullptr) {
        printf("Failed to find call map: %s\n", CILIUM_TAIL_CALL_MAP);
        return ERROR_NOT_FOUND;
    }

    fd_t call_map_fd = bpf_map__fd(call_map);

    // Iterate over all the programs and check the program names.
    struct bpf_program* program = nullptr;
    program = bpf_object__next_program(object, program);
    while (program != nullptr) {
        const char* name = bpf_program__name(program);
        index = _get_map_index_from_program_name(name);
        if (index >= 0) {
            fd_t prog_fd = bpf_program__fd(program);
            result = bpf_map_update_elem(call_map_fd, &index, &prog_fd, 0);
            if (result != ERROR_SUCCESS) {
                printf("Failed to update fd for program %s in tail call map\n", name);
                goto Exit;
            }
        }
        program = bpf_object__next_program(object, program);
    }

Exit:
    if (result != ERROR_SUCCESS) {
        // TODO: Cleanup the partially populated tail call map.
    }
    return result;
}

static uint32_t
_load_and_attach_xdp_program(_In_ const char* file)
{
    uint32_t error = ERROR_SUCCESS;
    bpf_object* object = nullptr;
    bpf_link* link = nullptr;
    bpf_program* entry_program = nullptr;
    bool program_attached = false;
    bool program_pinned = false;
    bool tail_call_map_populated = false;

    // Load the program.
    printf("Verifying the program ... \n");
    
    object = bpf_object__open(file);
    if (!object) {
        error = errno;
        printf("bpf_object__open failed with error %d\n", error);
        goto Exit;
    }

    // Get prog object for the "main" program.
    entry_program = bpf_object__find_program_by_name(object, XDP_ENTRY_PROGRAM);
    if (entry_program == nullptr) {
        printf("Failed to find entry program: %s\n", XDP_ENTRY_PROGRAM);
        error = errno;
        goto Exit;
    }

    if (bpf_program__set_type(entry_program, BPF_PROG_TYPE_XDP) < 0) {
        printf("Failed to set program type for entry program: %s\n", XDP_ENTRY_PROGRAM);
        error = errno;
        goto Exit;
    }

    printf("Loading and attaching the program to XDP hook ...\n");
    if (bpf_object__load(object) < 0) {
        error = errno;
        printf("bpf_object__load failed with error %d\n", error);
        goto Exit;
    }
    
    // Pin the program so that it is not unloaded when the daemon stops.
    if (bpf_program__pin(entry_program, XDP_PROGRAM_PIN_PATH) < 0) {
        printf("Failed to pin entry program: %s\n", XDP_ENTRY_PROGRAM);
        error = errno;
        goto Exit;
    }
    
    program_pinned = true;

    // Populate tail call map.
    error = _populate_tail_call_map(object);
    if (error != ERROR_SUCCESS) {
        goto Exit;
    }
    tail_call_map_populated = true;

    link = bpf_program__attach(entry_program);
    if (!link) {
        error = errno;
        goto Exit;
    }
    program_attached = true;

Exit:
    if (error != ERROR_SUCCESS) {
        if (program_pinned) {
            ebpf_object_unpin(XDP_PROGRAM_PIN_PATH);
        }
        if (program_attached) {
            bpf_link__destroy(link);
        }
        if (tail_call_map_populated) {
            // _clean_tail_call_map();
        }
    }
    if (object != nullptr) {
        bpf_object__close(object);
    }
    return error;
}

uint32_t
compile_and_load_xdp_program(_In_ const interface_info_t* info, lb_mode_t mode, bool track_code_flow)
{
    uint32_t result = ERROR_SUCCESS;

    // Compile the XDP program.
    result = _compile_xdp_program(info, mode, track_code_flow);
    if (result != ERROR_SUCCESS) {
        printf("Failed to compile XDP program for %s mode.\n", mode == LB_MODE_DSR ? "DSR" : "SNAT");
        return result;
    }

    // Now load and attach XDP program.
    std::string file_name("bpf_xdp_");
    file_name += (mode == LB_MODE_DSR ? "dsr.o" : "snat.o");
    result = _load_and_attach_xdp_program(file_name.c_str());
    if (result != ERROR_SUCCESS) {
        printf("Failed to load and attach the XDP program, error = %d\n", result);
        return result;
    }

    return ERROR_SUCCESS;
}

uint32_t
compile_xdp_program(_In_ const interface_info_t* info, lb_mode_t mode, bool track_code_flow)
{
    return _compile_xdp_program(info, mode, track_code_flow);
}

static uint32_t
_clean_tail_call_map_state()
{
    uint32_t error = ERROR_SUCCESS;
    fd_t invalid_fd = ebpf_fd_invalid;
    int array_size;

    // Get fd for the tail call map.
    std::string pin_path = get_map_pin_path(CILIUM_TAIL_CALL_MAP);
    fd_t map_fd = bpf_obj_get(pin_path.c_str());
    if (map_fd == ebpf_fd_invalid) {
        error = ERROR_NOT_FOUND;
        goto Exit;
    }

    array_size = sizeof(cilium_tail_call_maps) / sizeof(cilium_tail_call_maps[0]);
    for (int i = 0; i < array_size; i++) {
        error = bpf_map_update_elem(map_fd, &cilium_tail_call_maps[i].index, &invalid_fd, 0);
        if (error != ERROR_SUCCESS) {
            printf("Cleanup: Failed to reset index %d in tail call map\n,", cilium_tail_call_maps[i].index);
            goto Exit;
        }
    }

Exit:
    if (map_fd != ebpf_fd_invalid) {
        _close(map_fd);
    }

    return error;
}

uint32_t
clean_old_program_state()
{
    ebpf_result_t result;
    uint32_t error = ERROR_SUCCESS;
    fd_t entry_program_fd;

    // Cleanup the program array map.
    error = _clean_tail_call_map_state();
    if (error != ERROR_SUCCESS && error != ERROR_NOT_FOUND) {
        printf("Cleanup: Failed to clean tail call map entries.\n");
    }
    error = ERROR_SUCCESS;

    // Get the fd for the entry program from pin path.
    entry_program_fd = bpf_obj_get(XDP_PROGRAM_PIN_PATH);
    if (entry_program_fd == ebpf_fd_invalid) {
        // Did not find the program using the pin path. Bail.
        goto Exit;
    }

    // Unpin the main program.
    result = ebpf_object_unpin(XDP_PROGRAM_PIN_PATH);
    if (result != EBPF_SUCCESS) {
        printf("Cleanup: Failed to unpin program from path %s\n", XDP_PROGRAM_PIN_PATH);
    }

Exit:
    if (entry_program_fd != ebpf_fd_invalid) {
        _close(entry_program_fd);
    }
    return error;
}
