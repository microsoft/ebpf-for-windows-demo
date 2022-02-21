// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "daemon.h"
#include <map>
#include <random>
#include "map.h"
#include "murmur3.h"
#include "util.h"
#include "maglev.h"

uint32_t
compile_and_load_xdp_program(_In_ const interface_info_t* info, lb_mode_t mode, bool track_code_flow);

uint32_t
compile_xdp_program(_In_ const interface_info_t* info, lb_mode_t mode, bool track_code_flow);

uint32_t
clean_old_program_state();