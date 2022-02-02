// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "daemon.h"

uint32_t
add_or_update_service(_In_ service_params_t* service_params);

uint32_t
program_services_to_xdp_maps();

void
dump_service_state(uint32_t service_id);
