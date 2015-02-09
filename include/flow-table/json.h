/*
 * libflowtable: A user-space library for a Linux Kernel Flow API
 *
 * Copyright (C) 2015  Netronome.
 *
 * Contacts: Simon Horman <simon.horman@netronome.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef FLOW_TABLE_JSON_H
#define FLOW_TABLE_JSON_H

#include <stdbool.h>

#include <json-c/json.h>
#include <netlink/attr.h>

json_object *flow_table_nla_to_json(struct nlattr **attr);

int flow_table_json_to_nla(struct nl_msg *msg, struct json_object *jobj);

bool flow_table_json_check_type(struct json_object *jobj, const char *name);

#endif
