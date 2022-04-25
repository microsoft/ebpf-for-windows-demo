// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// daemon.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include "daemon.h"
#include "map.h"
#include "service.h"
#include "program.h"
#include "util.h"

#define OPTION_LB_MODE 1
#define OPTION_DEVICE 2
#define OPTION_DUMMY 3

#define LB_MODE_OPTION_STR "--bpf-lb-mode="
#define DEVICES_OPTION_STR "--device="
#define LB_MODE_OPTION_DSR_STR "dsr"
#define LB_MODE_OPTION_SNAT_STR "snat"

#define COMMAND_INVALID 0
#define COMMAND_SERVICE 1
#define COMMAND_NEIGHBOR 2
#define COMMAND_MODE 3
#define COMMAND_EXIT 4
#define COMMAND_EMPTY 5
#define COMMAND_CLEAR 6
#define COMMAND_UNLOAD 7

#define COMMAND_SERVICE_STR "service"
#define COMMAND_NEIGHBOR_STR "neighbor"
#define COMMAND_MODE_STR "mode"
#define COMMAND_EXIT_STR "exit"
#define COMMAND_EMPTY_STR ""
#define COMMAND_CLEAR_STR "cls"
#define COMMAND_UNLOAD_STR "unload"

#define SERVICE_UPDATE_STR "update"
#define SERVICE_DELETE_STR "delete"
#define SERVICE_DUMPSTATE_STR "dumpstate"
#define SERVICE_FRONTEND_STR "--frontend"
#define SERVICE_BACKENDS_STR "--backends"
#define SERVICE_ID_STR "--id"

global_config_t global_config;

static HANDLE _cleanup_event = nullptr;
static HANDLE _thread_handle = nullptr;

static uint32_t
_get_command(_In_ std::string& input, _Out_ uint32_t* command)
{
    std::string token;
    std::stringstream input_stream(input);
    int offset;
    *command = COMMAND_INVALID;

    if (getline(input_stream, token, ' ')) {
        // Got the first token. Check the command.
        if (offset = token.find(std::string(COMMAND_SERVICE_STR)) == 0) {
            *command = COMMAND_SERVICE;
            return ERROR_SUCCESS;
        } else if (offset = token.find(std::string(COMMAND_NEIGHBOR_STR)) == 0) {
            *command = COMMAND_NEIGHBOR;
            return ERROR_SUCCESS;
        } else if (offset = token.find(std::string(COMMAND_MODE_STR)) == 0) {
            *command = COMMAND_MODE;
            return ERROR_SUCCESS;
        } else if (offset = token.find(std::string(COMMAND_EXIT_STR)) == 0) {
            *command = COMMAND_EXIT;
            return ERROR_SUCCESS;
        } else if (offset = token.find(std::string(COMMAND_CLEAR_STR)) == 0) {
            *command = COMMAND_CLEAR;
            return ERROR_SUCCESS;
        } else if (offset = token.find(std::string(COMMAND_UNLOAD_STR)) == 0) {
            *command = COMMAND_UNLOAD;
            return ERROR_SUCCESS;
        }
    } else if (strcmp(input.c_str(), COMMAND_EMPTY_STR) == 0) {
        *command = COMMAND_EMPTY;
        return ERROR_SUCCESS;
    }

    return ERROR_INVALID_PARAMETER;
}

static uint32_t
_parse_mode_command(std::string& input, _Out_ lb_mode_t* mode)
{
    std::vector<std::string> tokens;
    std::string token;
    std::stringstream input_stream(input);
    std::string command;

    *mode = LB_MODE_INVALID;

    while (getline(input_stream, token, ' ')) {
        tokens.push_back(token);
    }

    if (tokens.size() != 3) {
        return ERROR_INVALID_PARAMETER;
    }

    // tokens[0] will be "mode"
    // tokens[1] should be "update"
    if (strcmp(tokens[1].c_str(), SERVICE_UPDATE_STR) != 0) {
        return ERROR_INVALID_PARAMETER;
    }

    if (strcmp(tokens[2].c_str(), LB_MODE_OPTION_DSR_STR) == 0) {
        *mode = lb_mode_t::LB_MODE_DSR;
    } else if (strcmp(tokens[2].c_str(), LB_MODE_OPTION_SNAT_STR) == 0) {
        *mode = lb_mode_t::LB_MODE_SNAT;
    } else {
        return ERROR_INVALID_PARAMETER;
    }

    return ERROR_SUCCESS;
}

static uint32_t
_parse_client_command(std::string& input, std::string& client_address)
{
    std::vector<std::string> tokens;
    std::string token;
    std::stringstream input_stream(input);
    std::string command;

    while (getline(input_stream, token, ' ')) {
        tokens.push_back(token);
    }

    if (tokens.size() != 3) {
        return ERROR_INVALID_PARAMETER;
    }

    // tokens[0] will be "client"
    // tokens[1] should be "update"
    if (strcmp(tokens[1].c_str(), SERVICE_UPDATE_STR) != 0) {
        return ERROR_INVALID_PARAMETER;
    }

    client_address = tokens[2];

    return ERROR_SUCCESS;
}

static uint32_t
_parse_service_command(std::string& input, service_params_t* params)
{
    std::vector<std::string> tokens;
    std::string token;
    std::stringstream input_stream(input);
    std::string command;

    while (getline(input_stream, token, ' ')) {
        tokens.push_back(token);
    }

    if (tokens.size() < 2) {
        return ERROR_INVALID_PARAMETER;
    }

    // tokens[0] will be "service"
    // tokens[1] should be "update", "delete" or "dumpstate"
    if (strcmp(tokens[1].c_str(), SERVICE_UPDATE_STR) == 0) {
        params->operation = service_operation_t::Update;
    } else if (strcmp(tokens[1].c_str(), SERVICE_DELETE_STR) == 0) {
        params->operation = service_operation_t::Delete;
    } else if (strcmp(tokens[1].c_str(), SERVICE_DUMPSTATE_STR) == 0) {
        params->operation = service_operation_t::DumpState;
    } else {
        // Invalid command.
        return ERROR_INVALID_PARAMETER;
    }

    if (params->operation == service_operation_t::Delete) {
        if (tokens.size() < 4) {
            return ERROR_INVALID_PARAMETER;
        }

        // If operation is delete, the next token should be SERVICE_ID_STR.
        if (strcmp(tokens[2].c_str(), SERVICE_ID_STR) != 0) {
            return ERROR_INVALID_PARAMETER;
        }

        // Next token should be service id.
        params->id = atoi(tokens[3].c_str());
    } else if (params->operation == service_operation_t::DumpState) {
        if (tokens.size() < 4) {
            return ERROR_INVALID_PARAMETER;
        }

        // If operation is dumpstate, the next token should be SERVICE_ID_STR.
        if (strcmp(tokens[2].c_str(), SERVICE_ID_STR) != 0) {
            return ERROR_INVALID_PARAMETER;
        }

        // Next token should be service id.
        params->id = atoi(tokens[3].c_str());
    } else {
        // Opertaion is update.
        bool found_frontend = false;
        bool found_backends = false;
        bool found_id = false;
        for (int i = 2; i < tokens.size(); i++) {
            // Further tokenize using '='
            std::vector<std::string> param_tokens;
            std::stringstream param_stream(tokens[i]);
            while (getline(param_stream, token, '=')) {
                param_tokens.push_back(token);
            }

            if (param_tokens.size() != 2) {
                return ERROR_INVALID_PARAMETER;
            }
            if (strcmp(param_tokens[0].c_str(), SERVICE_FRONTEND_STR) == 0) {
                // This is frontend. Further tokenize with ':'
                std::vector<std::string> frontend_tokens;
                std::stringstream frontend_stream(param_tokens[1]);
                while (getline(frontend_stream, token, ':')) {
                    frontend_tokens.push_back(token);
                }
                if (frontend_tokens.size() != 2) {
                    return ERROR_INVALID_PARAMETER;
                }
                params->frontend_ip = frontend_tokens[0];
                params->frontend_port = static_cast<uint16_t>(atoi(frontend_tokens[1].c_str()));

                found_frontend = true;
            } else if (strcmp(param_tokens[0].c_str(), SERVICE_BACKENDS_STR) == 0) {
                // There may be multiple backends. Tokenize with ','
                std::vector<std::string> backends_tokens;
                std::stringstream backends_stream(param_tokens[1]);
                while (getline(backends_stream, token, ',')) {
                    backends_tokens.push_back(token);
                }
                if (backends_tokens.size() < 1) {
                    // Minimum 1 backend should be provided.
                    return ERROR_INVALID_PARAMETER;
                }

                // Now tokenize each backend with ':'
                for (int j = 0; j < backends_tokens.size(); j++) {
                    std::vector<std::string> backend_tokens;
                    std::stringstream backend_stream(backends_tokens[j]);
                    while (getline(backend_stream, token, ':')) {
                        backend_tokens.push_back(token);
                    }
                    if (backend_tokens.size() != 2) {
                        return ERROR_INVALID_PARAMETER;
                    }
                    backend_params_t backend;
                    backend.backend_ip = backend_tokens[0];
                    backend.backend_port = static_cast<uint16_t>(atoi(backend_tokens[1].c_str()));
                    params->backends.emplace_back(backend);
                }
                found_backends = true;
            } else if (strcmp(param_tokens[0].c_str(), SERVICE_ID_STR) == 0) {
                params->id = atoi(param_tokens[1].c_str());
                found_id = true;
            } else {
                return ERROR_INVALID_PARAMETER;
            }
        }
        if (!found_backends || !found_frontend || !found_id) {
            return ERROR_INVALID_PARAMETER;
        }
    }

    return ERROR_SUCCESS;
}

static void
_update_daemon_mode(lb_mode_t new_mode)
{
    if (new_mode == global_config.mode) {
        printf("New and old mode same, ignoring.\n");
        return;
    }

    clean_old_program_state();
    clean_old_pinned_maps();

    uint32_t result = compile_and_load_xdp_program(&global_config.info, new_mode, false);
    if (result != ERROR_SUCCESS) {
        printf("Failed to compile and load XDP program. error=%d\n", result);
        global_config.mode = LB_MODE_INVALID;
        return;
    }

    // Add the services back.
    printf("Re-configuring configured services ... \n");
    result = program_services_to_xdp_maps();
    if (result != ERROR_SUCCESS) {
        global_config.mode = LB_MODE_INVALID;
        return;
    }

    global_config.mode = new_mode;
}

static void
_unload_xdp_program()
{
    clean_old_program_state();
    clean_old_pinned_maps();
}

DWORD WINAPI
thread_proc(_In_ LPVOID paramater)
{
    UNREFERENCED_PARAMETER(paramater);

    uint32_t result = ERROR_SUCCESS;
    uint32_t command;

    std::string input;
    printf("\n");
    while (true) {
        printf(">$ ");
        getline(std::cin, input);

        // Parse the input string. Command categories are:
        // 1. service
        // 2. neighbor
        // 3. mode
        // 4. exit
        // 5. empty
        // 6. clear
        // 7. unload
        result = _get_command(input, &command);
        if (result != ERROR_SUCCESS) {
            printf(">$ Invalid command\n");
            continue;
        }

        switch (command) {
        case COMMAND_EMPTY:
            break;
        case COMMAND_CLEAR:
            system(COMMAND_CLEAR_STR);
            break;
        case COMMAND_UNLOAD:
            _unload_xdp_program();
            set_foreground_color(foreground_color_t::green);
            printf("Successfully unloaded program(s)\n");
            reset_foreground_color();
            break;
        case COMMAND_SERVICE: {
            service_params_t service_params;
            result = _parse_service_command(input, &service_params);
            if (result != ERROR_SUCCESS) {
                printf(">$ Invalid command\n");
                continue;
            }

            if (service_params.operation == service_operation_t::DumpState) {
                dump_service_state(service_params.id);
                break;
            } else if (service_params.operation == service_operation_t::Update) {
                set_foreground_color(foreground_color_t::green);
                printf("Configuring service with id %d\n", service_params.id);
                set_foreground_color(foreground_color_t::yellow);
                add_or_update_service(&service_params);
                set_foreground_color(foreground_color_t::green);
                printf("Successfully configured service\n");
                reset_foreground_color();

                break;
            }
            break;
        }
        case COMMAND_NEIGHBOR: {
            std::string client_address;
            result = _parse_client_command(input, client_address);
            if (result != ERROR_SUCCESS) {
                printf(">$ Invalid command\n");
                continue;
            }
            update_neighbor_map_for_destination(client_address.c_str());
            break;
        }
        case COMMAND_MODE: {
            lb_mode_t mode;
            result = _parse_mode_command(input, &mode);
            if (result != ERROR_SUCCESS) {
                printf(">$ Invalid command\n");
                continue;
            }
            set_foreground_color(green);
            printf("Updating XDP mode to %s\n", (mode == LB_MODE_DSR ? "DSR" : "SNAT"));
            set_foreground_color(yellow);
            _update_daemon_mode(mode);
            set_foreground_color(green);
            printf("Successfully updated XDP mode to %s\n", (mode == LB_MODE_DSR ? "DSR" : "SNAT"));
            reset_foreground_color();

            break;
        }
        case COMMAND_EXIT: {
            SetEvent(_cleanup_event);
            goto Exit;
        }
        }
    }
Exit:
    return ERROR_SUCCESS;
}

_Success_(return == ERROR_SUCCESS) uint32_t _parse_command(_In_ const char* command, _Out_ uint32_t* option)
{
    std::string command_string(command);
    size_t offset = 0;
    if ((offset = command_string.find(std::string(LB_MODE_OPTION_STR))) == 0) {
        // --bpf-lb-mode=
        *option = OPTION_LB_MODE;
        return ERROR_SUCCESS;
    } else if ((offset = command_string.find(std::string(DEVICES_OPTION_STR))) == 0) {
        // --device=
        *option = OPTION_DEVICE;
        return ERROR_SUCCESS;
    }

    return ERROR_INVALID_PARAMETER;
}

uint32_t
_parse_startup_arguments(int argc, _In_ char* argv[])
{
    uint32_t option;
    for (int i = 1; i < argc; i++) {
        if (_parse_command(argv[i], &option) != ERROR_SUCCESS) {
            printf("error parsing paramater %s\n", argv[i]);
            return ERROR_INVALID_PARAMETER;
        }

        std::string command_string(argv[i]);
        if (option == OPTION_LB_MODE) {
            std::string option_string(argv[i] + strlen(LB_MODE_OPTION_STR));
            if (option_string.find(std::string(LB_MODE_OPTION_DSR_STR)) == 0) {
                // Mode is DSR
                global_config.mode = lb_mode_t::LB_MODE_DSR;
            } else if (option_string.find(std::string(LB_MODE_OPTION_SNAT_STR)) == 0) {
                // Mode is SNAT
                global_config.mode = lb_mode_t::LB_MODE_SNAT;
            } else {
                printf("error parsing paramater %s\n", argv[i]);
                return ERROR_INVALID_PARAMETER;
            }
        } else if (option == OPTION_DEVICE) {
            std::string option_string(argv[i] + strlen(DEVICES_OPTION_STR));
            global_config.info.name = get_wstring_from_string(option_string);
        } else {
            printf("error parsing paramater %s\n", argv[i]);
            return ERROR_INVALID_PARAMETER;
        }
    }

    return ERROR_SUCCESS;
}

static uint32_t
_initialize()
{
    uint32_t error = wsa_initialize();
    if (error != ERROR_SUCCESS) {
        printf("WSAStartup startup failed with error %d\n", error);
        return error;
    }

    initialize_map_entries();

    return ERROR_SUCCESS;
}

static void
_print_global_config()
{
    set_foreground_color(green);
    printf(
        "Initializing daemon with mode = %s\n",
        global_config.mode == LB_MODE_DSR ? LB_MODE_OPTION_DSR_STR : LB_MODE_OPTION_SNAT_STR);
    set_foreground_color(yellow);
    printf("Using interface:\n");
    printf("  name         = %ws\n", global_config.info.name.c_str());
    printf("  mtu          = %d\n", global_config.info.mtu);
    printf("  ifindex      = %d\n", global_config.info.ifIndex);
    if (global_config.v4_enabled) {
        printf("  IPv4 address = %s\n", address_to_string(&global_config.info.ipv4_address, AF_INET).c_str());
    }
    if (global_config.v6_enabled) {
        printf("  IPv6 address = %s\n", address_to_string(&global_config.info.ipv6_address, AF_INET6).c_str());
    }
    printf("\n");
}

int
main(int argc, char* argv[])
{
    uint32_t result;

    try {
        // Parse command line options.
        if (argc != 3) {
            printf("Invalid arguments\n");
            printf("Example command: daemon.exe --bpf-lb-mode=<dsr/snat> --device=<device>\n");
            return ERROR_INVALID_PARAMETER;
        }

        result = _parse_startup_arguments(argc, argv);
        if (result != ERROR_SUCCESS) {
            goto Exit;
        }

        result = _initialize();
        if (result != ERROR_SUCCESS) {
            printf("Initialize failed with error %d", result);
            goto Exit;
        }

        // Currently only enable IPv4.
        global_config.v4_enabled = true;
        global_config.v6_enabled = false;

        // Get interface properties.
        result = get_interface_properties(&global_config.info, global_config.v4_enabled, global_config.v6_enabled);
        if (result != ERROR_SUCCESS) {
            printf(
                "Failed to get interface properties for interface %ws, error %d\n",
                global_config.info.name.c_str(),
                result);
            goto Exit;
        }

        _print_global_config();

        // Initialize cleanup event.
        _cleanup_event = CreateEvent(nullptr, TRUE, FALSE, NULL);
        if (_cleanup_event == NULL) {
            printf("Failed to initialize cleanup event. Error=%d\n", GetLastError());
            goto Exit;
        }

        printf("Cleaning up previous configuration ...\n");
        clean_old_program_state();
        clean_old_pinned_maps();

        result = compile_and_load_xdp_program(&global_config.info, global_config.mode, false);
        if (result != ERROR_SUCCESS) {
            printf("Failed to compile and load XDP program. error=%d\n", result);
            goto Exit;
        }

        // Spawn thread to take input from user.
        _thread_handle = CreateThread(NULL, 0, thread_proc, nullptr, 0, nullptr);
        if (_thread_handle == nullptr) {
            printf("Failed to create worker thread. Error=%d\n", GetLastError());
            goto Exit;
        }

        set_foreground_color(green);
        printf("Initialization complete.\n");
        reset_foreground_color();
    } catch (const std::bad_alloc&) {
        printf("Memory allocation failed.\n");
        result = ERROR_NOT_ENOUGH_MEMORY;
        goto Exit;
    } catch (...) {
        printf("Initialize hit an exception.\n");
        result = ERROR_INVALID_PARAMETER;
        goto Exit;
    }

Exit:
    if (_cleanup_event) {
        CloseHandle(_cleanup_event);
    }
    if (_thread_handle) {
        WaitForSingleObject(_thread_handle, INFINITE);
    }

    reset_foreground_color();
    return 0;
}
