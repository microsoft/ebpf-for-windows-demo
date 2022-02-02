// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "daemon.h"

uint32_t
upsert_maglev_lookup_table(service_t* service);

uint32_t
delete_maglev_lookup_table(service_t* service);