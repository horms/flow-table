#ifndef FLOW_TABLE_MSG_H
#define FLOW_TABLE_MSG_H

#include <netlink/msg.h>

struct nl_msg * flow_table_msg_put(int family, int ifindex, int cmd);

#endif
