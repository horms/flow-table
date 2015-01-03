#include <lib/nla-policy.h>

#include <flow-table/json.h>
#include <flow-table/msg.h>

struct flow_table_nla_json_rule;

struct flow_table_nla_json_policy {
	unsigned int multi_element:1;
	const char *name;
	const struct flow_table_nla_json_rule *nested_rule;
	json_object *(*to_json)(struct nlattr *attr);
	int (*to_nla)(struct nl_msg *msg, json_object *jobj);
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

/* Write 64bit unsigned integer values as two unsigned 32bit values
 * stored in signed 64 bit objects */
static json_object *
flow_table_to_json_u64(uint64_t val)
{
	json_object *jobj, *high, *low;

	jobj = json_object_new_object();
	low = json_object_new_int64(val & 0xffffffff);
	high = json_object_new_int64((val >> 32) & 0xffffffff);
	if (!jobj || !low || !high) {
		json_object_put(jobj);
		json_object_put(high);
		json_object_put(low);
		return NULL;
	}

	json_object_object_add(jobj, "high", high);
	json_object_object_add(jobj, "low", low);

	return jobj;
}

/* Read 64bit unsigned integer values as two unsigned 32bit values
 * stored in signed 64 bit objects */
static int
flow_table_from_json_u64(json_object *jobj, uint64_t *val)
{
	json_object *high, *low;
	uint64_t l, h;

	if (!json_object_object_get_ex(jobj, "high", &high) ||
	    !json_object_object_get_ex(jobj, "low", &low))
		return -1;

	h = json_object_get_int64(high) & 0xffffffff;
	l = json_object_get_int64(low) & 0xffffffff;

	*val = (h << 32) | l;

	return 0;
}

static json_object *
flow_table_nla_to_json_field_ref(struct nlattr *attr)
{
	json_object *jobj;
	json_object *instance;
	json_object *header;
	json_object *field;
	json_object *mask_type;
	json_object *type;
	json_object *value;
	json_object *mask;
	struct net_flow_field_ref ref;

	if (flow_table_get_field_ref(&ref, attr))
		return NULL;

	jobj = json_object_new_object();
	instance = json_object_new_int(ref.instance);
	header = json_object_new_int(ref.header);
	field = json_object_new_int(ref.field);
	mask_type = json_object_new_int(ref.mask_type);
	type = json_object_new_int(ref.type);
	value = flow_table_to_json_u64(ref.value_u64);
	mask = flow_table_to_json_u64(ref.mask_u64);

	if (!jobj || !instance || !header || !field ||
	    !mask_type || !type || !value || !mask)
		goto err;

	json_object_object_add(jobj, "instance", instance);
	json_object_object_add(jobj, "header", header);
	json_object_object_add(jobj, "field", field);
	json_object_object_add(jobj, "mask_type", mask_type);
	json_object_object_add(jobj, "type", type);
	json_object_object_add(jobj, "value", value);
	json_object_object_add(jobj, "mask", mask);

	return jobj;

err:
	json_object_put(jobj);
	json_object_put(instance);
	json_object_put(header);
	json_object_put(field);
	json_object_put(mask_type);
	json_object_put(type);
	json_object_put(value);
	json_object_put(mask);
	return NULL;
}

static int
flow_table_json_to_nla_field_ref(struct nl_msg *msg, json_object *jobj)
{
	json_object *instance;
	json_object *header;
	json_object *field;
	json_object *mask_type;
	json_object *type;
	json_object *value;
	json_object *mask;
	uint64_t value_u64, mask_u64;
	struct net_flow_field_ref ref;

	if (!json_object_object_get_ex(jobj, "instance", &instance) ||
	    !json_object_object_get_ex(jobj, "header", &header) ||
	    !json_object_object_get_ex(jobj, "field", &field) ||
	    !json_object_object_get_ex(jobj, "mask_type", &mask_type) ||
	    !json_object_object_get_ex(jobj, "type", &type) ||
	    !json_object_object_get_ex(jobj, "value", &value) ||
	    !json_object_object_get_ex(jobj, "mask", &mask))
		return -1;

	ref.instance =	json_object_get_int(instance);
	ref.header =	json_object_get_int(header);
	ref.field =	json_object_get_int(field);
	ref.mask_type =	json_object_get_int(mask_type);
	ref.type =	json_object_get_int(type);

	if (flow_table_from_json_u64(value, &value_u64) ||
	    flow_table_from_json_u64(mask, &mask_u64))
		return -1;

	ref.value_u64 = value_u64;
	ref.mask_u64 = mask_u64;

	if (flow_table_put_field_ref(msg, &ref))
		return -1;

	return 0;
}

static json_object *
flow_table_nla_to_json_action_arg(struct nlattr *attr)
{
	json_object *jobj;
	json_object *name;
	json_object *type;
	json_object *value;
	struct net_flow_action_arg action_arg;

	if (flow_table_get_action_arg(&action_arg, attr))
		return NULL;

	jobj = json_object_new_object();
	name = json_object_new_string(action_arg.name);
	type = json_object_new_int(action_arg.type);
	value = flow_table_to_json_u64(action_arg.value_u64);

	if (!jobj || !name || !value)
		goto err;

	json_object_object_add(jobj, "name", name);
	json_object_object_add(jobj, "type", type);
	json_object_object_add(jobj, "value", value);

	return jobj;

err:
	json_object_put(jobj);
	json_object_put(name);
	json_object_put(type);
	json_object_put(value);
	return NULL;
}

static int
flow_table_json_to_nla_action_arg(struct nl_msg *msg, json_object *jobj)
{
	json_object *name;
	json_object *type;
	json_object *value;
	const char *name_str;
	uint64_t value_u64;
	struct net_flow_action_arg action_arg;

	if (!json_object_object_get_ex(jobj, "name", &name) ||
	    !json_object_object_get_ex(jobj, "type", &type) ||
	    !json_object_object_get_ex(jobj, "value", &value))
		return -1;

	name_str = json_object_get_string(name);
	action_arg.type = json_object_get_int(type);

	if (strlen(name_str) >= NET_FLOW_NAMSIZ)
		return -1;
	strcpy(action_arg.name, name_str);


	if (flow_table_from_json_u64(value, &value_u64))
		return -1;
	action_arg.value_u64 = value_u64;

	if (flow_table_put_action_arg(msg, &action_arg))
		return -1;

	return 0;
}

static struct flow_table_nla_json_policy flow_table_nla_json_field_ref_policy[NET_FLOW_FIELD_REF_MAX + 1] = {
        [NET_FLOW_FIELD_REF]	= {
		.to_json = flow_table_nla_to_json_field_ref,
		.to_nla	 = flow_table_json_to_nla_field_ref,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_field_ref_rule,
			      net_flow_field_ref_policy,
			      flow_table_nla_json_field_ref_policy,
			      NET_FLOW_FIELD_REF_MAX);

static struct flow_table_nla_json_policy flow_table_nla_json_action_arg_policy[NET_FLOW_ACTION_ARG_MAX + 1] = {
        [NET_FLOW_ACTION_ARG]	= {
		.to_json = flow_table_nla_to_json_action_arg,
		.to_nla	 = flow_table_json_to_nla_action_arg,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_action_arg_rule,
			      net_flow_action_arg_policy,
			      flow_table_nla_json_action_arg_policy,
			      NET_FLOW_ACTION_ARG_MAX);

static const struct flow_table_nla_json_policy flow_table_nla_json_action_policy[NET_FLOW_ATTR_MAX + 1] = {
        [NET_FLOW_ACTION_ATTR_NAME]	= { .name = "name" },
        [NET_FLOW_ACTION_ATTR_UID]	= { .name = "uid" },
        [NET_FLOW_ACTION_ATTR_SIGNATURE]= {
		.name = "signature",
		.multi_element = 1,
		.nested_rule = &flow_table_nla_json_action_arg_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_action_rule,
			      net_flow_action_policy,
			      flow_table_nla_json_action_policy,
			      NET_FLOW_ACTION_ATTR_MAX);

static struct flow_table_nla_json_policy flow_table_nla_json_act_policy[NET_FLOW_ACTION_MAX + 1] = {
        [NET_FLOW_ACTION]	= {
		.name = "action",
		.nested_rule = &flow_table_nla_json_action_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_act_rule, net_flow_act_policy,
			      flow_table_nla_json_act_policy, NET_FLOW_ACTION);

static const struct flow_table_nla_json_policy flow_table_nla_json_flow_policy[NET_FLOW_ATTR_MAX + 1] = {
        [NET_FLOW_ATTR_ERROR]	= { .name = "error" },
        [NET_FLOW_ATTR_TABLE]	= { .name = "table" },
        [NET_FLOW_ATTR_UID]	= { .name = "uid" },
        [NET_FLOW_ATTR_PRIORITY]= { .name = "priority" },
        [NET_FLOW_ATTR_MATCHES]	= {
		.name = "matches",
		.multi_element = 1,
		.nested_rule = &flow_table_nla_json_field_ref_rule,
	},
        [NET_FLOW_ATTR_ACTIONS]	= {
		.name = "actions",
		.multi_element = 1,
		.nested_rule = &flow_table_nla_json_act_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_flow_rule,
			      net_flow_flow_policy,
			      flow_table_nla_json_flow_policy,
			      NET_FLOW_ATTR_MAX);

static struct flow_table_nla_json_policy flow_table_nla_json_net_flow_policy[NET_FLOW_NET_FLOW_MAX + 1] = {
        [NET_FLOW_FLOW]	= {
		.name = "flow",
		.nested_rule = &flow_table_nla_json_flow_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_net_flow_rule,
			      net_flow_net_flow_policy,
			      flow_table_nla_json_net_flow_policy,
			      NET_FLOW_NET_FLOW_MAX);

static struct flow_table_nla_json_policy flow_table_nla_json_flows_policy[NET_FLOW_MAX + 1] = {
        [NET_FLOW_FLOWS]	= {
		.name = "flows",
		.multi_element = 1,
		.nested_rule = &flow_table_nla_json_net_flow_rule,
	},
};

static const
FLOW_TABLE_NLA_JSON_RULE_INIT(flow_table_nla_json_flows_rule, net_flow_policy,
			      flow_table_nla_json_flows_policy, NET_FLOW_MAX);

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

	if (!njp->name && !njp->to_json)
		return -1;

	switch (rule->nla_policy[type].type) {
	case NLA_UNSPEC:
		if (njp->multi_element || njp->name || !njp->to_json)
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
		if (njp->multi_element)
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

		if (!attrs[i] || (!njp->name && !njp->to_json))
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
	                                      &flow_table_nla_json_flows_rule))
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
		if (njp->multi_element ||
		    !njp->to_nla || njp->to_nla(msg, jobj))
			return -1;
		break;

	case NLA_U32:
		/* Unsigned 32bit values are stored in a signed 64 bit object
		 * as there is no unsigned 32bit object expoed by json-c */
		if (njp->multi_element || njp->to_json ||
		    nla_put_u32(msg, idx, json_object_get_int64(jobj)))
			return -1;
		break;

	case NLA_NESTED: {
		int err;
		struct nlattr *start;

		if (njp->to_json)
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
		unsigned maxlen;

		if (njp->multi_element)
			return -1;
		s = json_object_get_string(jobj);

		maxlen = rule->nla_policy[idx].maxlen;
		if (maxlen && strlen(s) > maxlen)
			return -1;
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
					     &flow_table_nla_json_flows_rule);
}

