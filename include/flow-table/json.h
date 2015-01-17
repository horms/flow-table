#ifndef FLOW_TABLE_JSON_H
#define FLOW_TABLE_JSON_H

#include <stdbool.h>

#include <json-c/json.h>
#include <netlink/attr.h>

json_object *flow_table_nla_to_json(struct nlattr **attr);

int flow_table_json_to_nla(struct nl_msg *msg, struct json_object *jobj);

bool flow_table_json_check_type(struct json_object *jobj, const char *name);

#endif
