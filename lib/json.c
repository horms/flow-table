#include <assert.h>
#include <stdbool.h>

#include "lib/nla-policy.h"
#include "lib/unused.h"

#include <flow-table/json.h>
#include <flow-table/msg.h>

struct flow_table_nla_json_rule;

struct flow_table_nla_json_policy {
	unsigned int multi_element:1;
	const char *name;
	const struct flow_table_nla_json_rule *nested_rule;
	json_object *(*to_json)(struct nlattr *attr);
	int (*to_nla)(struct nl_msg *msg, int attrtype, json_object *jobj);
};

struct flow_table_nla_json_rule {
	const struct flow_table_nla_json_policy *nla_json_policy;
	struct nla_policy *nla_policy;
	int policy_max;
};

#define FLOW_TABLE_NLA_JSON_RULE_INIT(name, nla, nla_json, max)	\
	struct flow_table_nla_json_rule name = {		\
		.nla_json_policy = nla_json,			\
		.nla_policy = nla,				\
		.policy_max = max,				\
	}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static int be_offset(int max, int i)
{
		return max - i;
}
#else
static int be_offset(int UNUSED(max), int i)
{
		return i;
}
#endif

static json_object *
flow_table_nla_to_json_binary(struct nlattr *attr)
{
	const uint8_t *data = nla_data(attr);
	int datalen = nla_len(attr);
	int i;
	json_object *array;

	array = json_object_new_array();

	for (i = 0; i < datalen; i++) {
		json_object *jobj;

		jobj = json_object_new_int(data[be_offset(datalen - 1, i)]);
		if (!jobj)
			goto err;

		if (json_object_array_add(array, jobj)) {
			json_object_put(jobj);
			goto err;
		}
	}

	return array;
err:
	json_object_put(array);
	return NULL;
}

static int
flow_table_json_to_nla_binary(struct nl_msg *msg, int attrtype,
			      json_object *jobj)
{
	int count, i;
	uint8_t *data;

	if (!json_object_is_type(jobj, json_type_array))
		return -1;

	count = json_object_array_length(jobj);

	data = malloc(count);
	if (!data)
		return -1;

	for (i = 0; i < count; i++) {
		struct json_object *e;
		uint8_t byte;

		e = json_object_array_get_idx(jobj, i);
		if (!e)
			return -1;

		byte = json_object_get_int(e) & 0xff;
		data[be_offset(count - 1, i)] = byte;
	}

	nla_put(msg, attrtype, count, data);
	free(data);

	return 0;
}

#define VARINT_ATTR(name_) {				\
	.name = (name_),				\
	.to_json = flow_table_nla_to_json_binary,	\
	.to_nla = flow_table_json_to_nla_binary,	\
}

static const struct flow_table_nla_json_policy flow_table_nla_json_field_ref_policy[NFL_FIELD_REF_MAX + 1] = {
	[NFL_FIELD_REF_NEXT_NODE] = { .name = "next_node" },
	[NFL_FIELD_REF_INSTANCE]  = { .name = "instance" },
	[NFL_FIELD_REF_HEADER]	  = { .name = "header" },
	[NFL_FIELD_REF_FIELD]	  = { .name = "field" },
	[NFL_FIELD_REF_MASK_TYPE] = { .name = "mask_type" },
	[NFL_FIELD_REF_TYPE]	  = { .name = "type" },
	[NFL_FIELD_REF_VALUE]	  = VARINT_ATTR("value"),
	[NFL_FIELD_REF_MASK]	  = VARINT_ATTR("mask"),
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_field_ref_rule,
			      flow_table_field_ref_policy,
			      flow_table_nla_json_field_ref_policy,
			      NFL_FIELD_REF_MAX);

static const struct flow_table_nla_json_policy flow_table_nla_json_field_refs_policy[NFL_FIELD_REFS_MAX + 1] = {
        [NFL_FIELD_REF]	= {
		.name = "field_ref",
		.nested_rule = &flow_table_nla_json_field_ref_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_field_refs_rule,
			      flow_table_field_refs_policy,
			      flow_table_nla_json_field_refs_policy,
			      NFL_FIELD_REFS_MAX);

static const struct flow_table_nla_json_policy flow_table_nla_json_action_arg_policy[NFL_ACTION_ARG_MAX + 1] = {
	[NFL_ACTION_ARG_NAME]  = { .name = "name" },
	[NFL_ACTION_ARG_TYPE]  = { .name = "type" },
	[NFL_ACTION_ARG_VALUE] = VARINT_ATTR("value"),
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_action_arg_rule,
			      flow_table_action_arg_policy,
			      flow_table_nla_json_action_arg_policy,
			      NFL_ACTION_ARG_MAX);

static const struct flow_table_nla_json_policy flow_table_nla_json_action_args_policy[NFL_ACTION_ARG_MAX + 1] = {
        [NFL_ACTION_ARG]	= {
		.name = "action_arg",
		.nested_rule = &flow_table_nla_json_action_arg_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_action_args_rule,
			      flow_table_action_args_policy,
			      flow_table_nla_json_action_args_policy,
			      NFL_ACTION_ARGS_MAX);

static const struct flow_table_nla_json_policy flow_table_nla_json_action_policy[NFL_ATTR_MAX + 1] = {
        [NFL_ACTION_ATTR_NAME]	= { .name = "name" },
        [NFL_ACTION_ATTR_UID]	= { .name = "uid" },
        [NFL_ACTION_ATTR_SIGNATURE]= {
		.name = "signature",
		.multi_element = 1,
		.nested_rule = &flow_table_nla_json_action_args_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_action_rule,
			      flow_table_action_policy,
			      flow_table_nla_json_action_policy,
			      NFL_ACTION_ATTR_MAX);

static const struct flow_table_nla_json_policy flow_table_nla_json_act_policy[NFL_ACTION_MAX + 1] = {
        [NFL_ACTION]	= {
		.name = "action",
		.nested_rule = &flow_table_nla_json_action_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_act_rule,
			      flow_table_act_policy,
			      flow_table_nla_json_act_policy, NFL_ACTION_MAX);

static const struct flow_table_nla_json_policy flow_table_nla_json_table_attr_policy[NFL_TABLE_ATTR_MAX + 1] = {
	[NFL_TABLE_ATTR_NAME]		= { .name = "name" },
	[NFL_TABLE_ATTR_UID]		= { .name = "uid" },
	[NFL_TABLE_ATTR_SOURCE]		= { .name = "source" },
	[NFL_TABLE_ATTR_APPLY]		= { .name = "apply" },
	[NFL_TABLE_ATTR_SIZE]		= { .name = "size" },
        [NFL_TABLE_ATTR_MATCHES]	= {
		.name = "matches",
		.multi_element = 1,
		.nested_rule = &flow_table_nla_json_field_refs_rule,
	},
        [NFL_TABLE_ATTR_ACTIONS]	= {
		.name = "actions",
		.multi_element = 1,
		/* N.B. flow_table_nla_json_act_policy is used for flows
		 * but not for tables which only have a list of action uids
		 */
		.nested_rule = &flow_table_nla_json_action_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_table_attr_rule,
			      flow_table_table_attr_policy,
			      flow_table_nla_json_table_attr_policy,
			      NFL_TABLE_ATTR_MAX);

static const struct flow_table_nla_json_policy flow_table_nla_json_table_policy[NFL_TABLE_MAX + 1] = {
	[NFL_TABLE]		= {
		.name = "table",
		.nested_rule = &flow_table_nla_json_table_attr_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_table_rule,
			      flow_table_table_policy,
			      flow_table_nla_json_table_policy, NFL_TABLE_MAX);

static const struct flow_table_nla_json_policy flow_table_nla_json_field_attr_policy[NFL_FIELD_ATTR_MAX + 1] = {
	[NFL_FIELD_ATTR_NAME]		= { .name = "name" },
	[NFL_FIELD_ATTR_UID]		= { .name = "uid" },
	[NFL_FIELD_ATTR_BITWIDTH]	= { .name = "bitwidth" },
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_field_attr_rule,
			      flow_table_field_attr_policy,
			      flow_table_nla_json_field_attr_policy,
			      NFL_FIELD_ATTR_MAX);

static const struct flow_table_nla_json_policy flow_table_nla_json_field_policy[NFL_HEADER_MAX + 1] = {
	[NFL_HEADER]		= {
		.name = "field",
		.nested_rule = &flow_table_nla_json_field_attr_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_field_rule,
			      flow_table_field_policy,
			      flow_table_nla_json_field_policy, NFL_HEADER_MAX);

static const struct flow_table_nla_json_policy flow_table_nla_json_header_attr_policy[NFL_HEADER_ATTR_MAX + 1] = {
	[NFL_HEADER_ATTR_NAME]		= { .name = "name" },
	[NFL_HEADER_ATTR_UID]		= { .name = "uid" },
	[NFL_HEADER_ATTR_FIELDS]	= {
		.name = "fields",
		.multi_element = 1,
		.nested_rule = &flow_table_nla_json_field_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_header_attr_rule,
			      flow_table_header_attr_policy,
			      flow_table_nla_json_header_attr_policy,
			      NFL_HEADER_ATTR_MAX);

static const struct flow_table_nla_json_policy flow_table_nla_json_header_policy[NFL_HEADER_MAX + 1] = {
	[NFL_HEADER]		= {
		.name = "header",
		.nested_rule = &flow_table_nla_json_header_attr_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_header_rule,
			      flow_table_header_policy,
			      flow_table_nla_json_header_policy, NFL_HEADER_MAX);

static const struct flow_table_nla_json_policy flow_table_nla_json_jump_entry_policy[NFL_JUMP_ENTRY_MAX + 1] = {
	[NFL_JUMP_ENTRY]	= {
		.name = "jump_entry",
		.multi_element = 1,
		.nested_rule = &flow_table_nla_json_field_ref_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_jump_entry_rule,
			      flow_table_jump_entry_policy,
			      flow_table_nla_json_jump_entry_policy,
			      NFL_JUMP_ENTRY_MAX);

static const struct flow_table_nla_json_policy flow_table_nla_json_header_node_hdrs_policy[NFL_HEADER_NODE_HDRS_MAX + 1] = {
	[NFL_HEADER_NODE_HDRS_VALUE]	= { .name = "value" },
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_header_node_hdrs_rule,
			      flow_table_header_node_hdrs_policy,
			      flow_table_nla_json_header_node_hdrs_policy,
			      NFL_HEADER_NODE_HDRS_MAX);

static const struct flow_table_nla_json_policy flow_table_nla_json_header_node_policy[NFL_HEADER_NODE_MAX + 1] = {
	[NFL_HEADER_NODE_NAME]		= { .name = "name" },
	[NFL_HEADER_NODE_UID]		= { .name = "uid" },
	[NFL_HEADER_NODE_HDRS]		= {
		.name = "hdrs",
		.multi_element = 1,
		.nested_rule = &flow_table_nla_json_header_node_hdrs_rule,

	},
	[NFL_HEADER_NODE_JUMP]		= {
		.name = "jump",
		.multi_element = 1,
		.nested_rule = &flow_table_nla_json_jump_entry_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_header_node_rule,
			      flow_table_header_node_policy,
			      flow_table_nla_json_header_node_policy,
			      NFL_HEADER_NODE_MAX);

static const struct flow_table_nla_json_policy flow_table_nla_json_header_graph_policy[NFL_HEADER_GRAPH_MAX + 1] = {
	[NFL_HEADER_GRAPH_NODE]		= {
		.name = "header_graph_node",
		.nested_rule = &flow_table_nla_json_header_node_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_header_graph_rule,
			      flow_table_header_graph_policy,
			      flow_table_nla_json_header_graph_policy,
			      NFL_HEADER_GRAPH_MAX);

static const struct flow_table_nla_json_policy flow_table_nla_json_table_graph_node_policy[NFL_TABLE_GRAPH_NODE_MAX + 1] = {
	[NFL_TABLE_GRAPH_NODE_UID]	= { .name = "uid" },
	[NFL_TABLE_GRAPH_NODE_FLAGS]	= { .name = "flags" },
	[NFL_TABLE_GRAPH_NODE_JUMP]	= {
		.name = "jump",
		.multi_element = 1,
		.nested_rule = &flow_table_nla_json_jump_entry_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_table_graph_node_rule,
			      flow_table_table_graph_node_policy,
			      flow_table_nla_json_table_graph_node_policy,
			      NFL_TABLE_GRAPH_NODE_MAX);

static const struct flow_table_nla_json_policy flow_table_nla_json_table_graph_policy[NFL_TABLE_GRAPH_MAX + 1] = {
	[NFL_TABLE_GRAPH_NODE]		= {
		.name = "table_graph_node",
		.nested_rule = &flow_table_nla_json_table_graph_node_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_table_graph_rule,
			      flow_table_table_graph_policy,
			      flow_table_nla_json_table_graph_policy,
			      NFL_TABLE_GRAPH_MAX);

static const struct flow_table_nla_json_policy flow_table_nla_json_rule_policy[NFL_ATTR_MAX + 1] = {
        [NFL_ATTR_ERROR]	= { .name = "error" },
        [NFL_ATTR_TABLE]	= { .name = "table" },
        [NFL_ATTR_UID]		= { .name = "uid" },
        [NFL_ATTR_PRIORITY]	= { .name = "priority" },
        [NFL_ATTR_MATCHES]	= {
		.name = "matches",
		.multi_element = 1,
		.nested_rule = &flow_table_nla_json_field_refs_rule,
	},
        [NFL_ATTR_ACTIONS]	= {
		.name = "actions",
		.multi_element = 1,
		.nested_rule = &flow_table_nla_json_act_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_rule_rule,
			      flow_table_rule_policy,
			      flow_table_nla_json_rule_policy,
			      NFL_ATTR_MAX);

static struct flow_table_nla_json_policy flow_table_nla_json_rule_policy__[NFL_NFL_MAX + 1] = {
        [NFL_FLOW]	= {
		.name = "flow",
		.nested_rule = &flow_table_nla_json_rule_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_rule_rule__,
			      flow_table_rule_policy__,
			      flow_table_nla_json_rule_policy__,
			      NFL_NFL_MAX);

static struct flow_table_nla_json_policy flow_table_nla_json_policy[NFL_MAX + 1] = {
        [NFL_TABLES]	= {
		.name = "tables",
		.multi_element = 1,
		.nested_rule = &flow_table_nla_json_table_rule,
	},
        [NFL_HEADERS]	= {
		.name = "headers",
		.multi_element = 1,
		.nested_rule = &flow_table_nla_json_header_rule,
	},
        [NFL_FLOWS]	= {
		.name = "flows",
		.multi_element = 1,
		.nested_rule = &flow_table_nla_json_rule_rule__,
	},
        [NFL_ACTIONS]	= {
		.name = "actions",
		.multi_element = 1,
		.nested_rule = &flow_table_nla_json_act_rule,
	},
        [NFL_HEADER_GRAPH]	= {
		.name = "header_graph",
		.multi_element = 1,
		.nested_rule = &flow_table_nla_json_header_graph_rule,
	},
        [NFL_TABLE_GRAPH]	= {
		.name = "table_graph",
		.multi_element = 1,
		.nested_rule = &flow_table_nla_json_table_graph_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_rule, flow_table_policy,
			      flow_table_nla_json_policy, NFL_MAX);

static json_object *
flow_table_nla_to_json_nested(struct nlattr *attr,
			      const struct flow_table_nla_json_rule *rule);

static json_object *
flow_table_nla_to_json_array(struct nlattr *attr,
			      const struct flow_table_nla_json_rule *rule);

static json_object *
flow_table_nla_to_json_one_nested(struct nlattr *attr,
				  const struct flow_table_nla_json_policy *njp)
{
	const struct flow_table_nla_json_rule *rule;

	rule = njp->nested_rule;

	if (njp->multi_element)
		return flow_table_nla_to_json_array(attr, rule);
	else
		return flow_table_nla_to_json_nested(attr, rule);
}

static bool
flow_table_check_nla_policy(const struct nlattr *attr,
			    const struct nla_policy *policy)
{
	unsigned maxlen = policy->maxlen;
	unsigned minlen = policy->minlen;
	int datalen = nla_len(attr);

	assert(datalen >= 0);
	assert(sizeof datalen == sizeof maxlen);

	return (!maxlen || (unsigned)datalen <= maxlen) &&
		(unsigned)datalen >= minlen;
}

static int
flow_table_nla_to_json_one(struct nlattr *attr, json_object *jobj,
			   const struct flow_table_nla_json_rule *rule)
{
	const struct flow_table_nla_json_policy *njp;
	int type;
	json_object *new_jobj;

	type = nla_type(attr);

	if (type > rule->policy_max)
		return -1;

	njp = rule->nla_json_policy + type;

	if (!njp->name)
		return -1;

	if (!flow_table_check_nla_policy(attr, rule->nla_policy + type))
	    return -1;

	switch (rule->nla_policy[type].type) {
	case NLA_UNSPEC:
		if (njp->multi_element || !njp->to_json)
			return -1;
		new_jobj = njp->to_json(attr);
		break;

	case NLA_U32:
		if (njp->multi_element || njp->to_json)
			return -1;
		/* Store unsigned 32bit in a signed 64 bit object.
		 * as there is no unsigned 32bit object expoed by json-c */
		new_jobj = json_object_new_int64(nla_get_u32(attr));
		break;

	case NLA_NESTED:
		if (njp->to_json)
			return -1;
		new_jobj = flow_table_nla_to_json_one_nested(attr, njp);
		break;

	case NLA_STRING:
		if (njp->multi_element || njp->to_json)
			return -1;
		new_jobj = json_object_new_string(nla_get_string(attr));
		break;

	default:
		return -1;
	}

	if (!new_jobj)
		return -1;

	if (json_object_is_type(jobj, json_type_array)) {
		json_object *o;

		if (njp->name) {
			o = json_object_new_object();
			if (!o) {
				json_object_put(new_jobj);
				return -1;
			}
		} else {
			o = new_jobj;
		}

		if (json_object_array_add(jobj, o)) {
			json_object_put(o);
			json_object_put(new_jobj);
			return -1;
		}

		if (njp->name)
			json_object_object_add(o, njp->name, new_jobj);
	} else if (!njp->name) {
		return -1;
	} else {
		json_object_object_add(jobj, njp->name, new_jobj);
	}

	return 0;
}

static json_object *
flow_table_nla_to_json_array(struct nlattr *attr,
			     const struct flow_table_nla_json_rule *rule)
{
	int rem;
	json_object *array;
	struct nlattr *a;

	array = json_object_new_array();
	if (!array)
		return NULL;

	nla_for_each_nested(a, attr, rem)
		if (flow_table_nla_to_json_one(a, array, rule))
			goto err;

	return array;
err:
	json_object_put(array);
	return NULL;
}

static int
flow_table_nla_to_json_attr_array(struct nlattr **attrs, json_object *jobj,
				  const struct flow_table_nla_json_rule *rule)
{
	int i;

	if (!attrs || !jobj || !rule)
		return -1;

	for (i = 0; i < rule->policy_max + 1; i++) {
		const struct flow_table_nla_json_policy *njp;

		njp = rule->nla_json_policy + i;

		if (!attrs[i] || !njp->name)
			continue;

		if (flow_table_nla_to_json_one(attrs[i], jobj, rule))
			return -1;
	}

	return 0;
}

static json_object *
flow_table_nla_to_json_nested(struct nlattr *attr,
			      const struct flow_table_nla_json_rule *rule)
{
	struct nlattr **attrs;
	json_object *jobj = NULL;

	if (!attr || !rule)
		return NULL;

	attrs = calloc(rule->policy_max + 1, sizeof *attrs);
	if (!attrs)
		return NULL;

	jobj = json_object_new_object();
	if (!jobj)
		goto err;

	if (nla_parse_nested(attrs, rule->policy_max, attr, rule->nla_policy))
		goto err;

	if (flow_table_nla_to_json_attr_array(attrs, jobj, rule))
		goto err;

	free(attrs);
	return jobj;

err:
	json_object_put(jobj);
	free(attrs);
	return NULL;
}

json_object *
flow_table_nla_to_json(struct nlattr **attr)
{
	json_object *jobj;

	jobj = json_object_new_object();
	if (!jobj)
		return NULL;

	if (flow_table_nla_to_json_attr_array(attr, jobj,
	                                      &flow_table_nla_json_rule))
		goto err;

	return jobj;

err:
	json_object_put(jobj);
	return NULL;
}

static int
flow_table_json_to_nla_array(struct nl_msg *msg, struct json_object *jobj,
			     const struct flow_table_nla_json_rule *rule);

static int
flow_table_json_to_nla_object(struct nl_msg *msg, struct json_object *jobj,
			     const struct flow_table_nla_json_rule *rule);

static int
flow_table_nla_json_rule_anonymous(const struct flow_table_nla_json_rule *rule)
{
	return rule->policy_max == 1 && rule->nla_policy[1].type == NLA_UNSPEC;
}

static int
flow_table_nla_json_rule_get_index(const struct flow_table_nla_json_rule *rule,
				   const char *name)
{
	int i;

	if (flow_table_nla_json_rule_anonymous(rule))
		return 1;

	if (!name)
		return -1;

	for (i = 1; i < rule->policy_max + 1; i++)
		if (rule->nla_json_policy[i].name &&
		    !strcmp(name, rule->nla_json_policy[i].name))
			return i;

	return -1;
}

static int
flow_table_json_to_nla_one(struct nl_msg *msg, const char *key,
			   struct json_object *jobj,
			   const struct flow_table_nla_json_rule *rule)
{
	int idx;
	const struct flow_table_nla_json_policy *njp;

	idx = flow_table_nla_json_rule_get_index(rule, key);
	if (idx < 0)
		return -1;

	njp = rule->nla_json_policy + idx;

	switch (rule->nla_policy[idx].type) {
	case NLA_UNSPEC:
		if (njp->multi_element || !njp->to_nla ||
		    njp->to_nla(msg, idx, jobj))
			return -1;
		break;

	case NLA_U32:
		/* Unsigned 32bit values are stored in a signed 64 bit object
		 * as there is no unsigned 32bit object expoed by json-c */
		if (njp->multi_element || njp->to_nla ||
		    nla_put_u32(msg, idx, json_object_get_int64(jobj)))
			return -1;
		break;

	case NLA_NESTED: {
		int err;
		struct nlattr *start;

		if (njp->to_nla)
			return -1;

		start = nla_nest_start(msg, idx);
		if (!start)
			return -1;

		if (json_object_is_type(jobj, json_type_array))
			err = flow_table_json_to_nla_array(msg, jobj,
							   njp->nested_rule);
		else
			err = flow_table_json_to_nla_object(msg, jobj,
							    njp->nested_rule);

		if (err) {
			nla_nest_cancel(msg, start);
			return -1;
		}

		nla_nest_end(msg, start);
		break;
	}

	case NLA_STRING: {
		const char *s;

		if (njp->multi_element || njp->to_nla)
			return -1;
		s = json_object_get_string(jobj);

		nla_put_string(msg, idx, s);
		break;
	}

	default:
		return -1;
	}

	return 0;
}

static int
flow_table_json_to_nla_array(struct nl_msg *msg, struct json_object *jobj,
			     const struct flow_table_nla_json_rule *rule)
{
	int i, count;

	if (!json_object_is_type(jobj, json_type_array))
		return -1;

	count = json_object_array_length(jobj);

	for (i = 0; i < count; i++) {
		struct json_object *e;
		int err;

		e = json_object_array_get_idx(jobj, i);
		if (!e)
			return -1;

		if (flow_table_nla_json_rule_anonymous(rule))
			/* Anonymous elements */
			err = flow_table_json_to_nla_one(msg, NULL, e, rule);
		else
			/* Named elements */
			err = flow_table_json_to_nla_object(msg, e, rule);
		if (err)
			return -1;
	}

	return 0;
}

static int
flow_table_json_to_nla_object(struct nl_msg *msg, struct json_object *jobj,
			      const struct flow_table_nla_json_rule *rule)
{
	struct json_object_iter iter;

	if (!json_object_is_type(jobj, json_type_object))
		return -1;

	json_object_object_foreachC(jobj, iter)
		if (flow_table_json_to_nla_one(msg, iter.key, iter.val, rule))
		    return -1;

	return 0;
}

int
flow_table_json_to_nla(struct nl_msg *msg, struct json_object *jobj)
{
	return flow_table_json_to_nla_object(msg, jobj,
					     &flow_table_nla_json_rule);
}

bool
flow_table_json_check_type(struct json_object *jobj, const char *name)
{
         struct json_object_iter iter;
         int i = 0;

         if (!json_object_is_type(jobj, json_type_object))
                 return false;

         json_object_object_foreachC(jobj, iter)
                 if (i++ > 0 || strcmp(name, iter.key))
                         return false;

         return true;
}
