#ifndef FLOW_TABLE_DATA_H
#define FLOW_TABLE_DATA_H

#include <sys/socket.h>

#include <linux/if_flow.h>

#include <flow-table/types.h>

void
flow_table_free_actions(struct net_flow_action *actions);

#endif
