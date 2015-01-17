/* Baed in part by flow_table.c by John Fastabend */

#include <limits.h>
#include <stdlib.h>

#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>

#include <lib/nla-policy.h>

#include <flow-table/data.h>
#include <flow-table/msg.h>

static int
flow_table_put_field_ref_desc(struct nl_msg *msg,
			      const struct net_flow_field_ref *ref)
{
	if (nla_put_u32(msg, NFL_FIELD_REF_INSTANCE, ref->instance) ||
	    nla_put_u32(msg, NFL_FIELD_REF_HEADER, ref->header) ||
	    nla_put_u32(msg, NFL_FIELD_REF_FIELD, ref->field) ||
	    nla_put_u32(msg, NFL_FIELD_REF_MASK_TYPE, ref->mask_type) ||
	    nla_put_u32(msg, NFL_FIELD_REF_TYPE, ref->type))
		return -1;

	return 0;
}

static int
flow_table_put_field_ref_value(struct nl_msg *msg,
			       const struct net_flow_field_ref *ref)
{
	int err = -1;

	switch (ref->type) {
	case NFL_FIELD_REF_ATTR_TYPE_UNSPEC:
		return 0;

	case NFL_FIELD_REF_ATTR_TYPE_U8:
		err = nla_put_u8(msg, NFL_FIELD_REF_VALUE, ref->value_u8);
		if (err)
			break;
		err = nla_put_u8(msg, NFL_FIELD_REF_MASK, ref->mask_u8);
		break;

	case NFL_FIELD_REF_ATTR_TYPE_U16:
		err = nla_put_u16(msg, NFL_FIELD_REF_VALUE, ref->value_u16);
		if (err)
			break;
		err = nla_put_u16(msg, NFL_FIELD_REF_MASK, ref->mask_u16);
		break;

	case NFL_FIELD_REF_ATTR_TYPE_U32:
		err = nla_put_u32(msg, NFL_FIELD_REF_VALUE, ref->value_u32);
		if (err)
			break;
		err = nla_put_u32(msg, NFL_FIELD_REF_MASK, ref->mask_u32);
		break;

	case NFL_FIELD_REF_ATTR_TYPE_U64:
		err = nla_put_u64(msg, NFL_FIELD_REF_VALUE, ref->value_u64);
		if (err)
			break;
		err = nla_put_u64(msg, NFL_FIELD_REF_MASK, ref->mask_u64);
		break;

	default:
		break;
	}

	return err ? -1 : 0;
}

int
flow_table_put_field_ref(struct nl_msg *msg,
			 const struct net_flow_field_ref *ref)
{
	if (flow_table_put_field_ref_desc(msg, ref) ||
	    flow_table_put_field_ref_value(msg, ref))
		return -1;

	return 0;
}

int
flow_table_put_field_refs(struct nl_msg *msg,
			  const struct net_flow_field_ref *refs)
{
	int i;

	for (i = 0; refs[i].header; i++)
		if (flow_table_put_field_ref(msg, &refs[i]))
			return -1;

	return 0;
}

int
flow_table_put_action_arg(struct nl_msg *msg,
			  const struct net_flow_action_arg *arg)
{
	struct nlattr *start;
	int err;

	start = nla_nest_start(msg, NFL_ACTION_ARG);
	if (!arg)
		return -1;

	if (arg->name) {
		err = nla_put_string(msg, NFL_ACTION_ARG_NAME,
				     arg->name);
		if (err)
			goto out;
	}

	err = nla_put_u32(msg, NFL_ACTION_ARG_TYPE, arg->type);
	if (err)
		goto out;

	switch (arg->type) {
	case NFL_ACTION_ARG_TYPE_NULL:
		err = 0;
		break;
	case NFL_ACTION_ARG_TYPE_U8:
		err = nla_put_u8(msg, NFL_ACTION_ARG_VALUE,
				 arg->value_u8);
		break;
	case NFL_ACTION_ARG_TYPE_U16:
		err = nla_put_u16(msg, NFL_ACTION_ARG_VALUE,
				  arg->value_u16);
		break;
	case NFL_ACTION_ARG_TYPE_U32:
		err = nla_put_u32(msg, NFL_ACTION_ARG_VALUE,
				  arg->value_u32);
		break;
	case NFL_ACTION_ARG_TYPE_U64:
		err = nla_put_u64(msg, NFL_ACTION_ARG_VALUE,
				  arg->value_u64);
		break;
	default:
		err = -1;
		break;
	}

	if (err)
		goto out;

	nla_nest_end(msg, start);
	return 0;
out:
	nla_nest_cancel(msg, start);
	return err;
}

int
flow_table_put_action_args(struct nl_msg *msg,
			   const struct net_flow_action_arg *args)
{
	int i;

	for (i = 0; args[i].type; i++)
		if (flow_table_put_action_arg(msg, &args[i]))
			return -1;

	return 0;
}

int
flow_table_put_action(struct nl_msg *msg, const struct net_flow_action *action)
{
	struct nlattr *action_start;
	struct nlattr *sigs_start;

	action_start = nla_nest_start(msg, NFL_ACTION);
	if (!action_start)
		return -1;

	if (action->name &&
	    nla_put_string(msg, NFL_ACTION_ATTR_NAME, action->name))
		goto err;

	if (nla_put_u32(msg, NFL_ACTION_ATTR_UID, action->uid))
		goto err;


	sigs_start = nla_nest_start(msg, NFL_ACTION_ATTR_SIGNATURE);
	if (!sigs_start)
		goto err;

	if (flow_table_put_action_args(msg, action->args)) {
		nla_nest_cancel(msg, sigs_start);
		goto err;
	}

	nla_nest_end(msg, sigs_start);
	nla_nest_end(msg, action_start);
	return 0;

err:
	nla_nest_cancel(msg, action_start);
	return -1;
}

int
flow_table_put_actions(struct nl_msg *msg,
		       const struct net_flow_action *actions)
{
	int i;

	for (i = 0; actions[i].uid; i++)
		if (flow_table_put_action(msg, &actions[i]))
			return -1;

	return 0;
}

int
flow_table_put_rule(struct nl_msg *msg, const struct net_flow_rule *rule)
{
	int err;
	struct nlattr *start;

	start = nla_nest_start(msg, NFL_FLOW);
	if (!start)
		return -1;

	if (nla_put_u32(msg, NFL_ATTR_TABLE, rule->table_id) ||
	    nla_put_u32(msg, NFL_ATTR_UID, rule->uid) ||
	    nla_put_u32(msg, NFL_ATTR_PRIORITY, rule->priority)) {
		nla_nest_cancel(msg, start);
		return -1;
	}

	if (rule->matches) {
		struct nlattr *matches;

		matches = nla_nest_start(msg, NFL_ATTR_MATCHES);
		if (!matches)
			goto err;

		err = flow_table_put_field_refs(msg, rule->matches);
		if (err) {
			nla_nest_cancel(msg, matches);
			goto err;
		}

		nla_nest_end(msg, matches);
	}


	if (rule->actions) {
		struct nlattr *actions;

		actions = nla_nest_start(msg, NFL_ATTR_ACTIONS);
		if (!actions)
			goto err;

		err = flow_table_put_actions(msg, rule->actions);
		if (err) {
			nla_nest_cancel(msg, actions);
			goto err;
		}

		nla_nest_end(msg, actions);
	}

	nla_nest_end(msg, start);
	return 0;

err:
	nla_nest_cancel(msg, start);
	return -1;
}

int
flow_table_put_flows_desc(struct nl_msg *msg, int table,
			  int min_prio, int max_prio)
{
	struct nlattr *start;

	start = nla_nest_start(msg, NFL_FLOWS);
	if (!start)
		return -1;

	if (nla_put_u32(msg, NFL_TABLE_FLOWS_TABLE, table))
		goto err;

	if (min_prio >= 0 &&
	    nla_put_u32(msg, NFL_TABLE_FLOWS_MINPRIO, min_prio))
		goto err;

	if (max_prio >= 0 &&
	    nla_put_u32(msg, NFL_TABLE_FLOWS_MAXPRIO, max_prio))
		goto err;

	nla_nest_end(msg, start);

	return 0;
err:
	nla_nest_cancel(msg, start);
	return -1;
}

int
flow_table_put_flows(struct nl_msg *msg,
		     int (*cb)(struct nl_msg *msg, void *data),
		     void *cb_data)
{
	int err;
	struct nlattr *start;

	start = nla_nest_start(msg, NFL_FLOWS);
	if (!start)
		return -1;

	err = cb(msg, cb_data);
	if (err) {
		nla_nest_cancel(msg, start);
		return -1;
	}

	nla_nest_end(msg, start);
	return 0;
}

struct nl_msg *
flow_table_msg_put(int family, int ifindex, int cmd)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return NULL;

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family,
			 0, 0, cmd, NFL_GENL_VERSION) ||
	    nla_put_u32(msg, NFL_IDENTIFIER_TYPE,
			 NFL_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(msg, NFL_IDENTIFIER, ifindex)) {
		free(msg);
		return NULL;
	}

	return msg;
}

struct nl_msg *
flow_table_msg_put_get_flows_request(int family, int ifindex, int table,
				     int min_prio, int max_prio)
{
	int err;
	struct nl_msg *msg;

	msg = flow_table_msg_put(family, ifindex,
				 NFL_TABLE_CMD_GET_FLOWS);

	err = flow_table_put_flows_desc(msg, table, min_prio, max_prio);
	if (err) {
		free(msg);
		return NULL;
	}

	return msg;
}

struct nl_msg *
flow_table_msg_put_set_flows_request(int family, int ifindex,
				     int (*cb)(struct nl_msg *msg, void *data),
				     void *cb_data)
{
	int err;
	struct nl_msg *msg;

	msg = flow_table_msg_put(family, ifindex,
				 NFL_TABLE_CMD_SET_FLOWS);

	err = flow_table_put_flows(msg, cb, cb_data);
	if (err) {
		free(msg);
		return NULL;
	}

	return msg;
}

int
flow_table_get_ifindex(struct nlattr **attrs)
{
	uint32_t ifindex, type;

	if (!attrs || !attrs[NFL_IDENTIFIER_TYPE] ||
	    !attrs[NFL_IDENTIFIER])
		return -1;

	type = nla_get_u32(attrs[NFL_IDENTIFIER_TYPE]);
	ifindex = nla_get_u32(attrs[NFL_IDENTIFIER]);

	if (type != NFL_IDENTIFIER_IFINDEX || ifindex > INT_MAX)
		return -1;

	return ifindex;
}

int
flow_table_get_table_flows(struct nlattr *attr, int *table, int *min_prio,
			   int *max_prio)
{
	int err;
	struct nlattr *attrs[NFL_TABLE_FLOWS_MAX + 1];
	uint32_t utable, umin_prio, umax_prio;

	if (!attr)
		return -1;

	err = nla_parse_nested(attrs, NFL_TABLE_FLOWS_MAX, attr,
                               flow_table_table_flows_policy);
        if (err)
		return -1;

	if (!attrs[NFL_TABLE_FLOWS_TABLE])
		return -1;

	utable = nla_get_u32(attrs[NFL_TABLE_FLOWS_TABLE]);
	if (utable > INT_MAX)
		return -1;
	else
		*table = utable;

        if (attrs[NFL_TABLE_FLOWS_MINPRIO]) {
                umin_prio = nla_get_u32(attrs[NFL_TABLE_FLOWS_MINPRIO]);
		if (umin_prio > INT_MAX)
			return -1;
		else
			*min_prio = umin_prio;
	} else {
		*min_prio = -1;
	}
        if (attrs[NFL_TABLE_FLOWS_MAXPRIO]) {
                umax_prio = nla_get_u32(attrs[NFL_TABLE_FLOWS_MAXPRIO]);
		if (umax_prio > INT_MAX)
			return -1;
		else
			*max_prio = umax_prio;
	} else {
		*max_prio = -1;
	}

	return 0;
}

int
flow_table_get_field_ref(struct net_flow_field_ref *ref, struct nlattr *attr)
{
	struct nlattr *attrs[NFL_FIELD_REF_MAX + 1];

	if (nla_parse_nested(attrs, NFL_FIELD_REF_MAX,
			     attr, flow_table_field_ref_policy))
		return -1;

	if (!attrs[NFL_FIELD_REF_INSTANCE] || !attrs[NFL_FIELD_REF_HEADER] ||
	    !attrs[NFL_FIELD_REF_FIELD] || !attrs[NFL_FIELD_REF_MASK_TYPE] ||
	    !attrs[NFL_FIELD_REF_TYPE])
		return -1;

	ref->instance = nla_get_u32(attrs[NFL_FIELD_REF_INSTANCE]);
	ref->header = nla_get_u32(attrs[NFL_FIELD_REF_HEADER]);
	ref->field = nla_get_u32(attrs[NFL_FIELD_REF_FIELD]);
	ref->mask_type = nla_get_u32(attrs[NFL_FIELD_REF_MASK_TYPE]);
	ref->type = nla_get_u32(attrs[NFL_FIELD_REF_TYPE]);

	if (!attrs[NFL_FIELD_REF_VALUE])
		return 0;

	switch (ref->type) {
	case NFL_FIELD_REF_ATTR_TYPE_U8:
		if (nla_len(attrs[NFL_FIELD_REF_VALUE]) <
		    (ssize_t)sizeof(uint8_t))
			return -1;
		ref->value_u8 = nla_get_u8(attrs[NFL_FIELD_REF_VALUE]);

		if (!attrs[NFL_FIELD_REF_MASK])
			break;

		if (nla_len(attrs[NFL_FIELD_REF_MASK]) <
		    (ssize_t)sizeof(uint8_t))
			return -1;
		ref->mask_u8 = nla_get_u8(attrs[NFL_FIELD_REF_MASK]);
		break;

	case NFL_FIELD_REF_ATTR_TYPE_U16:
		if (nla_len(attrs[NFL_FIELD_REF_VALUE]) <
		    (ssize_t)sizeof(uint16_t))
			return -1;
		ref->value_u16 = nla_get_u16(attrs[NFL_FIELD_REF_VALUE]);

		if (!attrs[NFL_FIELD_REF_MASK])
			break;

		if (nla_len(attrs[NFL_FIELD_REF_MASK]) <
		    (ssize_t)sizeof(uint16_t))
			return -1;
		ref->mask_u16 = nla_get_u16(attrs[NFL_FIELD_REF_MASK]);
		break;

	case NFL_FIELD_REF_ATTR_TYPE_U32:
		if (nla_len(attrs[NFL_FIELD_REF_VALUE]) <
		    (ssize_t)sizeof(uint32_t))
			return -1;
		ref->value_u32 = nla_get_u32(attrs[NFL_FIELD_REF_VALUE]);

		if (!attrs[NFL_FIELD_REF_MASK])
			break;

		if (nla_len(attrs[NFL_FIELD_REF_MASK]) <
		    (ssize_t)sizeof(uint32_t))
			return -1;
		ref->mask_u32 = nla_get_u32(attrs[NFL_FIELD_REF_MASK]);
		break;

	case NFL_FIELD_REF_ATTR_TYPE_U64:
		if (nla_len(attrs[NFL_FIELD_REF_VALUE]) <
		    (ssize_t)sizeof(uint64_t))
			return -1;
		ref->value_u64 = nla_get_u64(attrs[NFL_FIELD_REF_VALUE]);

		if (!attrs[NFL_FIELD_REF_MASK])
			return -1;

		if (nla_len(attrs[NFL_FIELD_REF_MASK]) <
		    (ssize_t)sizeof(uint64_t))
			return -1;
		ref->mask_u64 = nla_get_u64(attrs[NFL_FIELD_REF_MASK]);
		break;
	}

	return 0;
}

struct net_flow_field_ref *
flow_table_get_field_refs(struct nlattr *attr)
{
	int count, rem;
	struct nlattr *a;
	struct net_flow_field_ref *refs;

	count = 0;
	nla_for_each_nested(a, attr, rem)
		if (nla_type(a) == NFL_FIELD_REF)
			count++;

	refs = calloc(count + 1, sizeof *refs);
	if (!refs)
		return NULL;

	count = 0;
	nla_for_each_nested(a, attr, rem) {
		if (flow_table_get_field_ref(&refs[count++], a)) {
			free(refs);
			return NULL;
		}
	}

	return refs;
}

int
flow_table_get_action_arg(struct net_flow_action_arg *arg, struct nlattr *attr)
{
	struct nlattr *attrs[NFL_ACTION_ARG_MAX + 1];

	if (nla_parse_nested(attrs, NFL_ACTION_ARG_MAX, attr,
			     flow_table_action_arg_policy))
		return -1;

	if (!attrs[NFL_ACTION_ARG_TYPE] || !attrs[NFL_ACTION_ARG_VALUE])
		return -1;

	arg->type = nla_get_u32(attrs[NFL_ACTION_ARG_TYPE]);
	switch (arg->type) {
	case NFL_ACTION_ARG_TYPE_U8:
		if (nla_len(attrs[NFL_ACTION_ARG_VALUE]) <
		    (ssize_t)sizeof(uint8_t))
			return -1;
		arg->value_u8 = nla_get_u8(attrs[NFL_ACTION_ARG_VALUE]);
		break;
	case NFL_ACTION_ARG_TYPE_U16:
		if (nla_len(attrs[NFL_ACTION_ARG_VALUE]) <
		    (ssize_t)sizeof(uint16_t))
			return -1;
		arg->value_u16 = nla_get_u16(attrs[NFL_ACTION_ARG_VALUE]);
		break;
	case NFL_ACTION_ARG_TYPE_U32:
		if (nla_len(attrs[NFL_ACTION_ARG_VALUE]) <
		    (ssize_t)sizeof(uint32_t))
			return -1;
		arg->value_u32 = nla_get_u32(attrs[NFL_ACTION_ARG_VALUE]);
		break;
	case NFL_ACTION_ARG_TYPE_U64:
		if (nla_len(attrs[NFL_ACTION_ARG_VALUE]) <
		    (ssize_t)sizeof(uint64_t))
			return -1;
		arg->value_u64 = nla_get_u64(attrs[NFL_ACTION_ARG_VALUE]);
		break;
	default:
		return -1;
	}

	if (attrs[NFL_ACTION_ARG_NAME]) {
		int max = nla_len(attrs[NFL_ACTION_ARG_NAME]);

		if (max > NFL_MAX_NAME)
			max = NFL_MAX_NAME;

		arg->name = malloc(max);
		if (!arg->name)
			return -1;
		memset(arg->name, 0, max);
		nla_strlcpy(arg->name, attrs[NFL_ACTION_ARG_NAME], max);
	}

	return 0;
}

int
flow_table_get_action(struct nlattr *attr, struct net_flow_action *action)
{
	int count, err, rem;
	struct nlattr *a;
	struct nlattr *attrs[NFL_ACTION_ATTR_MAX + 1];

	err = nla_parse_nested(attrs, NFL_ACTION_ATTR_MAX,
			       attr, flow_table_action_policy);
	if (err < 0)
		return -1;

        if (!attrs[NFL_ACTION_ATTR_UID] ||
            !attrs[NFL_ACTION_ATTR_SIGNATURE])
                return -1;

        action->uid = nla_get_u32(attrs[NFL_ACTION_ATTR_UID]);

	if (attrs[NFL_ACTION_ATTR_NAME]) {
		const char *name;

		name = nla_get_string(attrs[NFL_ACTION_ATTR_NAME]);
		action->name = strdup(name);
		if (!name)
			goto err;
	}

	count = 0;
	nla_for_each_nested(a, attrs[NFL_ACTION_ATTR_SIGNATURE], rem)
		if (nla_type(a) == NFL_ACTION_ARG)
			count++;

	action->args = calloc(count + 1, sizeof *action->args);
	if (!action->args)
		goto err;

	count = 0;
	nla_for_each_nested(a, attrs[NFL_ACTION_ATTR_SIGNATURE], rem) {
		if (nla_type(a) != NFL_ACTION_ARG)
			continue;

		if (flow_table_get_action_arg(&action->args[count++], a)) {
			goto err;
		}
	}

	return 0;
err:
	free(action->name);
	free(action->args);
	return -1;
}

struct net_flow_action *
flow_table_get_actions(struct nlattr *attr)
{
	int count, rem;
	struct nlattr *a;
	struct net_flow_action *actions;

	count = 0;
	nla_for_each_nested(a, attr, rem)
		count++;

	actions = calloc(count + 1, sizeof *actions);

	count = 0;
	nla_for_each_nested(a, attr, rem) {
		if (flow_table_get_action(a, actions + count++)) {
			flow_table_free_actions(actions);
			return NULL;
		}
	}

	return actions;
}

int
flow_table_get_rule(struct nlattr *attr, struct net_flow_rule *rule)
{
	int err;
	struct nlattr *attrs[NFL_ATTR_MAX + 1];


	err = nla_parse_nested(attrs, NFL_ATTR_MAX, attr,
			       flow_table_rule_policy);
	if (err)
		return -1;

        if (!attrs[NFL_ATTR_TABLE] || !attrs[NFL_ATTR_UID] ||
            !attrs[NFL_ATTR_PRIORITY])
                return -1;

        rule->table_id = nla_get_u32(attrs[NFL_ATTR_TABLE]);
        rule->uid = nla_get_u32(attrs[NFL_ATTR_UID]);
        rule->priority = nla_get_u32(attrs[NFL_ATTR_PRIORITY]);

        rule->matches = NULL;
        rule->actions = NULL;

        if (attrs[NFL_ATTR_MATCHES]) {
		rule->matches = flow_table_get_field_refs(attrs[NFL_ATTR_MATCHES]);
		if (!rule->matches)
			return -1;
        }

        if (attrs[NFL_ATTR_ACTIONS]) {
		rule->actions = flow_table_get_actions(attrs[NFL_ATTR_ACTIONS]);
		if (!rule->actions) {
			free(rule->matches);
			return -1;
		}
        }

        return 0;
}

int
flow_table_get_flow_flows(struct nlattr *attr,
			  int (*cb)(const struct net_flow_rule *rule,
				    void *data),
			  void *cb_data)
{
	int err, rem;
	struct nlattr *a;

	nla_for_each_nested(a, attr, rem) {
		struct net_flow_rule rule;

		if (nla_type(a) != NFL_FLOW)
			continue;

		err = flow_table_get_rule(a, &rule);
		if (err)
			return -1;

		err = cb(&rule, cb_data);

		free(rule.matches);
		flow_table_free_actions(rule.actions);

		if (err)
			return -1;
	}

	return 0;
}

static int
flow_table_get_index_and_attrs_from_request(struct nlattr *attr,
					    struct nlattr **attrs)
{
	int err, ifindex;

	if (!attr)
		return -1;

	err = nla_parse_nested(attrs, NFL_MAX, attr, flow_table_policy);
	if (err)
		return -1;

	ifindex = flow_table_get_ifindex(attrs);
	if (ifindex < 0)
		return -1;

	return ifindex;
}

int
flow_table_get_ifindex_from_request(struct nlattr *attr)
{
	struct nlattr *attrs[NFL_MAX+1];

	return flow_table_get_index_and_attrs_from_request(attr, attrs);
}

int
flow_table_get_get_flows_request(struct nlattr *attr, int *table,
				 int *max_prio, int *min_prio)
{
	int err, ifindex;
	struct nlattr *attrs[NFL_MAX+1];

	ifindex = flow_table_get_index_and_attrs_from_request(attr, attrs);
	if (ifindex < 0)
		return -1;

	err = flow_table_get_table_flows(attrs[NFL_FLOWS], table,
					 max_prio, min_prio);
	if (err)
		return -1;

	return ifindex;
}

int
flow_table_flows_request(struct nlattr *attr,
			 int (*cb)(const struct net_flow_rule *rule,
				   void *data),
			 void *cb_data)
{
	int err;
	struct nlattr *attrs[NFL_MAX+1];
	int ifindex;

	if (!attr)
		return -1;

	err = nla_parse_nested(attrs, NFL_MAX, attr, flow_table_policy);
	if (err)
		return -1;

	ifindex = flow_table_get_ifindex(attrs);
	if (ifindex < 0)
		return -1;

	err = flow_table_get_flow_flows(attrs[NFL_FLOWS], cb, cb_data);
	if (err)
		return -1;

	return ifindex;
}
