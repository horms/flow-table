#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/socket.h>

#include <linux/if_flow.h>

#include <net/ethernet.h>

#include <flow-table/msg.h>

#include "flow-table-ctl/log.h"
#include "flow-table-ctl/unused.h"

#define PROG_NAME "flow-table-ctl"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

static void
usage(void)
{
	fprintf(stderr,
		"Usage: " PROG_NAME "command \n"
		"commands:\n"
		"\tadd-flow interface flow\n"
		"\tdump-flows interface\n");
	exit(EXIT_FAILURE);
}

static int
get_flows_rsp_cb(const struct net_flow_flow *flow, void *UNUSED(data))
{
	flow_table_log_warn("Got Flow:\n"
			    "  table_id=%d uid=%d priority=%d\n"
			    "  has %sactions\n"
			    "  has %smatches\n",
			    flow->table_id, flow->uid, flow->priority,
			    flow->actions ? "" : "no ",
			    flow->matches ? "" : "no ");
	return 0;
}

/* XXX: Copied from msg.c */
static struct nla_policy net_flow_policy[NET_FLOW_MAX + 1] =
{
	[NET_FLOW_IDENTIFIER_TYPE]	= { .type = NLA_U32 },
	[NET_FLOW_IDENTIFIER]		= { .type = NLA_U32 },
	[NET_FLOW_TABLES]		= { .type = NLA_NESTED },
	[NET_FLOW_HEADERS]		= { .type = NLA_NESTED },
	[NET_FLOW_ACTIONS]		= { .type = NLA_NESTED },
	[NET_FLOW_HEADER_GRAPH]		= { .type = NLA_NESTED },
	[NET_FLOW_TABLE_GRAPH]		= { .type = NLA_NESTED },
	[NET_FLOW_FLOWS]		= { .type = NLA_NESTED },
	[NET_FLOW_FLOWS_ERROR]		= { .type = NLA_NESTED },
};

static int
msg_handler(struct nl_msg *msg, void *arg)
{
	int err, ifindex;
	int *expected_ifindex = arg;
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct genlmsghdr *gehdr = genlmsg_hdr(hdr);
	struct nlattr *attrs[NET_FLOW_MAX+1];

	err = genlmsg_parse(hdr, 0, attrs, NET_FLOW_MAX,
			    net_flow_policy);
	if (err) {
		flow_table_log_fatal("could not parse top level attributes\n");
		return NL_SKIP;
	}

	ifindex = flow_table_get_ifindex(attrs);
	if (ifindex < 0) {
		flow_table_log_fatal("could not parse preamble\n");
		return NL_SKIP;
	}

	if (ifindex != *expected_ifindex) {
		flow_table_log_fatal("ifindex missmatc\n");
		return NL_SKIP;
	}

	switch (gehdr->cmd) {
	case NET_FLOW_TABLE_CMD_GET_FLOWS:
		if (flow_table_get_flow_flows(attrs[NET_FLOW_FLOWS],
					      get_flows_rsp_cb, NULL))
			break;
		return NL_OK;

	case NET_FLOW_TABLE_CMD_SET_FLOWS:
		flow_table_log_warn("spurious NET_FLOW_TABLE_CMD_SET_FLOWS "
				    "message\n");
		break;

	default:
		flow_table_log_warn("unknown command (%d) in message\n",
				    gehdr->cmd);
		break;
	}

	return NL_SKIP;
}

static int
link_name2i(const char *ifname)
{
	int err, ifindex;
	struct nl_cache *link_cache = NULL;
	struct nl_sock *sock = NULL;

	sock = nl_socket_alloc();
	if (!sock)
		flow_table_log_fatal("Could not allocate netlink socket\n");

	err = nl_connect(sock, NETLINK_ROUTE);
	if (err < 0)
		flow_table_log_fatal("Could not connection to netlink "
				     "socket: %s\n", nl_geterror(err));

	err = rtnl_link_alloc_cache(sock, AF_UNSPEC, &link_cache);
	if (!link_cache)
		flow_table_log_fatal("Could not allocate link cache: %s\n",
				     nl_geterror(err));

	ifindex = rtnl_link_name2i(link_cache, ifname);
	if (!ifindex)
		flow_table_log_fatal("Could not find interface \"%s\"\n",
				     ifname);

	nl_cache_free(link_cache);
	nl_socket_free(sock);

	return ifindex;
}

/* XXX: Only dumps table 0 and never uses min or max prio */
static void
do_dump_flows(struct nl_sock *sock, int family, int ifindex,
	      int UNUSED(argc), char * const *UNUSED(argv))
{
	struct nl_msg *msg;
	int err;

	msg = flow_table_msg_put_get_flows_request(family, ifindex, 0, -1, -1);
	if (!msg)
		flow_table_log_fatal("error putting netlink message\n");

	err = nl_send_auto(sock, msg);
	if (err < 0)
		 flow_table_log_fatal("error sending netlink message: %s\n",
				      nl_geterror(err));

	err = nl_recvmsgs_default(sock);
	if (err < 0)
		 flow_table_log_fatal("error receiving netlink message: %s\n",
				      nl_geterror(err));

	free(msg);
}

/* XXX: Only supports unmasked dl_dst match which is arbitrarily
 * hard coded to header=2,field=2,type=u64 */
static const char *parse_field_refs(const char *flow_str,
				    struct net_flow_field_ref **refs)
{
	const char *key = "dl_dst=";
	int n, bytes;
	uint8_t dl_dst[ETHER_ADDR_LEN];

	if (strncmp(flow_str, key, strlen(key)))
		flow_table_log_fatal("Unknown match in flow \"%s\"\n",
				     flow_str);

	n = sscanf(flow_str + strlen(key),
		   "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%n",
		   &dl_dst[0], &dl_dst[1], &dl_dst[2],
		   &dl_dst[3], &dl_dst[4], &dl_dst[5], &bytes);
	if (n != 6)
		flow_table_log_fatal("Invalid dl address in match in flow "
				     "\"%s\"\n", flow_str);

	*refs = calloc(2, sizeof **refs);
	if (!*refs)
		flow_table_log_fatal("Out of memory\n");

	/* XXX: Too much magic here! */
	(*refs)[0].header = 1;
	(*refs)[0].field = 2;
	(*refs)[0].type = NET_FLOW_FIELD_REF_ATTR_TYPE_U64;
	memcpy((uint8_t *)&(*refs)[0].value_u64, dl_dst, sizeof dl_dst);

	return flow_str + strlen(key) + bytes;
}

/* XXX: No actions are supported */
static const char *parse_actions(const char *actions_str)
{
	if (*actions_str)
		return NULL;

	return actions_str;
}

static int
add_flow_cb(struct nl_msg *msg, void *data)
{
	return flow_table_put_flow(msg, data);
}

/* XXX: Always uses table and priority 0 and random uid.
 * Does not support any actions */
static void
do_add_flow(struct nl_sock *sock, int family, int ifindex,
	    int UNUSED(argc), char * const *argv)
{
	const char *flow_str = argv[0];
	const char *s;
	int err;
	struct net_flow_flow flow = { .table_id = 0 };
	struct nl_msg *msg;

	srandom(time(NULL) * getpid());
	flow.uid = random() & 0x7fffffff;

	s = parse_field_refs(flow_str, &flow.matches);
	if (!s)
		 flow_table_log_fatal("error parsing matches\n");
	s = parse_actions(s);
	if (!s)
		 flow_table_log_fatal("error parsing actions\n");

	msg = flow_table_msg_put_set_flows_request(family, ifindex,
						   add_flow_cb, &flow);
	if (!msg)
		flow_table_log_fatal("error putting netlink message\n");

	err = nl_send_auto(sock, msg);
	if (err < 0)
		 flow_table_log_fatal("error sending netlink message: %s\n",
				      nl_geterror(err));

	err = nl_recvmsgs_default(sock);
	if (err < 0)
		 flow_table_log_fatal("error receiving netlink message: %s\n",
				      nl_geterror(err));

	free(flow.matches);
	free(msg);
}

static const struct cmd {
	const char *name;
	int min_argc;
	int max_argc;
	void (*cb)(struct nl_sock *sock, int family, int ifindex,
		   int argc, char * const *argv);
} cmds[] = {
	{
		.name = "dump-flows",
		.cb = do_dump_flows,
		.min_argc = 0,
		.max_argc = 0,
	},
	{
		.name = "add-flow",
		.cb = do_add_flow,
		.min_argc = 1,
		.max_argc = 1,
	},
};

void
do_cmd(struct nl_sock *sock, int family, int ifindex,
       const char *cmd_name, int argc, char * const *argv)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
		const struct cmd *cmd = &cmds[i];

		if (strcmp(cmd->name, cmd_name))
			continue;

		if (argc < cmd->min_argc) {
			flow_table_log_err("Too few arguments to command "
					   "\"%s\"\n\n", cmd_name);
			usage();
		}

		if (argc > cmd->max_argc) {
			flow_table_log_err("Too many arguments to command "
					   "\"%s\"\n\n", cmd_name);
			usage();
		}

		return cmd->cb(sock, family, ifindex, argc, argv);
	}

	flow_table_log_err("Unsupported command \"%s\"\n\n", cmd_name);
	usage();
}

int
main(int argc, char **argv)
{
	const char *cmd_name, *ifname;
	int err, ifindex, family;
	struct nl_sock *sock = NULL;

	if (argc < 3) {
		flow_table_log_err("Too few arguments\n\n");
		usage();
	}

	cmd_name = argv[1];
	ifname = argv[2];

	sock = nl_socket_alloc();
	if (!sock)
		flow_table_log_fatal("Could not allocate netlink socket\n");

	err = genl_connect(sock);
	if (err < 0)
		flow_table_log_fatal("Could not connection to netlink "
				     "socket: %s\n", nl_geterror(err));

	family = genl_ctrl_resolve(sock, NET_FLOW_GENL_NAME);
	if (family < 0)
		flow_table_log_fatal("error resolving generic netlink family "
				     "\"" NET_FLOW_GENL_NAME "\": %s\n",
				     nl_geterror(family));

	ifname = argv[2];
	ifindex = link_name2i(ifname);

	printf("family is %d; index is %d\n", family, ifindex);

	err = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM,
				  msg_handler, &ifindex);
	if (err)
		flow_table_log_fatal("error modifying callback: %s\n",
				     nl_geterror(err));

	do_cmd(sock, family, ifindex, cmd_name, argc - 3, argv + 3);

	nl_socket_free(sock);

	return 0;
}
