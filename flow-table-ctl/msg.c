#include <netlink/genl/genl.h>

#include <linux/if_flow.h>

#include "flow-table-ctl/log.h"
#include "flow-table-ctl/msg.h"

struct nl_msg *
flow_table_msg_put(int family, int ifindex, int cmd)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		flow_table_log_fatal("Could not allocate netlink message\n");

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family,
			 0, 0, cmd, NET_FLOW_GENL_VERSION) ||
	    nla_put_u32(msg, NET_FLOW_IDENTIFIER_TYPE,
			 NET_FLOW_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(msg, NET_FLOW_IDENTIFIER, ifindex))
		flow_table_log_fatal("Could put netlink message\n");

	return msg;
}
