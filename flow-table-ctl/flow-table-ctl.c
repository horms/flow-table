#include <sys/types.h>

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>

#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/socket.h>

#include <linux/if_flow.h>

#include <net/ethernet.h>

#include <flow-table/json.h>
#include <flow-table/msg.h>

#include "lib/unused.h"

#include "flow-table-ctl/log.h"

#define PROG_NAME "flow-table-ctl"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

static void
usage(void)
{
	fprintf(stderr,
		"Usage: " PROG_NAME "command \n"
		"commands:\n"
		"\tget-flows interface [table_id [min_prio [max_prio]]]\n"
		"\tset-flows interface filename\n"
		"\tdel-flows interface filename\n");
	exit(EXIT_FAILURE);
}

static int
print_flows(struct nlattr **attrs)
{
	json_object *jobj;

	if (!attrs)
		return -1;
	jobj = flow_table_nla_to_json(attrs);
	if (!jobj)
		return -1;

	printf("%s\n", json_object_to_json_string_ext(jobj,
						      JSON_C_TO_STRING_PRETTY));
	return 0;
}

/* XXX: Copied from nla-policy.c */
static struct nla_policy net_flow_policy[NFL_MAX + 1] =
{
	[NFL_IDENTIFIER_TYPE]	= { .type = NLA_U32 },
	[NFL_IDENTIFIER]	= { .type = NLA_U32 },
	[NFL_TABLES]		= { .type = NLA_NESTED },
	[NFL_HEADERS]		= { .type = NLA_NESTED },
	[NFL_ACTIONS]		= { .type = NLA_NESTED },
	[NFL_HEADER_GRAPH]	= { .type = NLA_NESTED },
	[NFL_TABLE_GRAPH]	= { .type = NLA_NESTED },
	[NFL_FLOWS]		= { .type = NLA_NESTED },
	[NFL_FLOWS_ERROR]	= { .type = NLA_NESTED },
};

static int
msg_handler(struct nl_msg *msg, void *arg)
{
	int err, ifindex;
	int *expected_ifindex = arg;
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct genlmsghdr *gehdr = genlmsg_hdr(hdr);
	struct nlattr *attrs[NFL_MAX + 1];

	err = genlmsg_parse(hdr, 0, attrs, NFL_MAX,
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
	case NFL_TABLE_CMD_GET_FLOWS:
		if (print_flows(attrs)) {
			flow_table_log_fatal("error printing flows\n");
			break;
		}
		return NL_OK;

	case NFL_TABLE_CMD_SET_FLOWS:
		flow_table_log_warn("spurious NFL_TABLE_CMD_SET_FLOWS "
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

static int
str_to_int(const char *nptr)
{
	long int l;

	l = strtol(nptr, NULL, 10);
	if (((l == LONG_MIN || l == LONG_MAX) || errno == ERANGE) ||
	    (l < INT_MIN || l > INT_MAX))
		flow_table_log_fatal("error converting integer to string: "
				     "out of range\n");

	return l;
}

static void
do_get_flows(struct nl_sock *sock, int family, int ifindex,
	      int argc, char * const *argv)
{
	struct nl_msg *msg;
	int err;
	long int table_id, min_prio, max_prio;

	table_id = argc > 0 ? str_to_int(argv[0]) : 0;
	min_prio = argc > 1 ? str_to_int(argv[1]) : -1;
	max_prio = argc > 2 ? str_to_int(argv[2]) : -1;

	msg = flow_table_msg_put_get_flows_request(family, ifindex,
						   table_id, min_prio,
						   max_prio);
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

static void
set_del_flows(struct nl_sock *sock, int family, int ifindex, int cmd,
	      const char *filename)
{
	int err;
	struct json_object *flows;
	struct nl_msg *msg;

	flows = json_object_from_file(filename);
	if (!flows)
		 flow_table_log_fatal("error parsing flows from file \'%s\'\n",
				      filename);

	msg = flow_table_msg_put(family, ifindex, cmd);
	if (!msg)
		flow_table_log_fatal("error putting netlink message\n");

	if (flow_table_json_to_nla(msg, flows))
		flow_table_log_fatal("error converting json to netlink\n");

	err = nl_send_auto(sock, msg);
	if (err < 0)
		 flow_table_log_fatal("error sending netlink message: %s\n",
				      nl_geterror(err));

	err = nl_recvmsgs_default(sock);
	if (err < 0)
		 flow_table_log_fatal("error receiving netlink message: %s\n",
				      nl_geterror(err));

	json_object_put(flows);
	free(msg);
}

static void
do_set_flows(struct nl_sock *sock, int family, int ifindex,
	     int UNUSED(argc), char * const *argv)
{
	set_del_flows(sock, family, ifindex, NFL_TABLE_CMD_SET_FLOWS,
		      argv[0]);
}

static void
do_del_flows(struct nl_sock *sock, int family, int ifindex,
	     int UNUSED(argc), char * const *argv)
{
	set_del_flows(sock, family, ifindex, NFL_TABLE_CMD_DEL_FLOWS,
		      argv[0]);
}

static const struct cmd {
	const char *name;
	int min_argc;
	int max_argc;
	void (*cb)(struct nl_sock *sock, int family, int ifindex,
		   int argc, char * const *argv);
} cmds[] = {
	{
		.name = "get-flows",
		.cb = do_get_flows,
		.min_argc = 0,
		.max_argc = 3,
	},
	{
		.name = "set-flows",
		.cb = do_set_flows,
		.min_argc = 1,
		.max_argc = 1,
	},
	{
		.name = "del-flows",
		.cb = do_del_flows,
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

	family = genl_ctrl_resolve(sock, NFL_GENL_NAME);
	if (family < 0)
		flow_table_log_fatal("error resolving generic netlink family "
				     "\"" NFL_GENL_NAME "\": %s\n",
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
