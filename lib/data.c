#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <flow-table/data.h>

bool
flow_table_field_ref_cmp(const struct net_flow_field_ref *a,
		       const struct net_flow_field_ref *b)
{
	return a->header == b->header && a->field == b->field &&
		a->mask_u64 == b->mask_u64 &&
		(a->value_u64 & a->mask_u64) == (b->value_u64 & b->mask_u64);
}

static bool
flow_table_field_refs_cmp__(const struct net_flow_field_ref *a,
			    const struct net_flow_field_ref *b)
{
	int i, j;

	for (i = 0; a[i].header; i++) {
		bool hit = false;

		for (j = 0; b[j].header; j++) {
			if (flow_table_field_ref_cmp(a + i, b + j)) {
				hit = true;
				break;
			}
		}

		if (!hit)
			return false;
	}

	return true;
}

bool
flow_table_field_refs_cmp(const struct net_flow_field_ref *a,
			  const struct net_flow_field_ref *b)
{
	return flow_table_field_refs_cmp__(a, b) &&
		flow_table_field_refs_cmp__(b, a);
}

struct net_flow_field_ref *
flow_table_field_refs_clone(struct net_flow_field_ref *refs)
{
	int count = 0;
	struct net_flow_field_ref *r;

	while (refs[count].header)
		count++;

	r = malloc((count + 1) * sizeof(*r));
	if (!r)
		return NULL;

	memcpy(r, refs, count * sizeof(*r));
	memset(r + count, 0, sizeof *r);

	return r;
}

struct net_flow_action_arg *
flow_table_action_arg_clone(struct net_flow_action_arg *args)
{
	int count = 0;
	struct net_flow_action_arg *a;

	while (args[count].type)
		count++;

	a = malloc((count + 1) * sizeof(*a));
	if (!a)
		return NULL;

	memcpy(a, args, count * sizeof(*a));
	memset(a + count, 0, sizeof *a);

	return a;
}

void
flow_table_free_actions(struct net_flow_action *actions)
{
	int i;

	if (!actions)
		return;

	for (i = 0; actions[i].uid; i++)
		free(actions[i].args);

	free(actions);
}

struct net_flow_action *
flow_table_actions_clone(const struct net_flow_action *actions)
{
	int count = 0;
	struct net_flow_action *a;

	while (actions[count].uid)
		count++;

	a = malloc((count + 1) * sizeof(*a));
	if (!a)
		return NULL;

	memcpy(a, actions, count * sizeof(*a));
	memset(a + count, 0, sizeof *a);

	for (count = 0; actions[count].uid; count++) {
		a[count].args = flow_table_action_arg_clone(actions[count].args);
		if (!a[count].args)
			flow_table_free_actions(a);
	}

	return a;
}

int
flow_table_flow_clone_data(struct net_flow_flow *dest,
			   const struct net_flow_flow *src)
{
	dest->table_id = src->table_id;
	dest->uid = src->uid;
	dest->priority = src->priority;

	if (src->matches) {
		dest->matches = flow_table_field_refs_clone(src->matches);
		if (!dest->matches)
			return -1;
	} else {
		dest->matches = NULL;
	}

	if (src->actions) {
		dest->actions = flow_table_actions_clone(src->actions);
		if (!src->actions) {
			free(dest->matches);
			return -1;
		}
	} else {
		dest->actions = NULL;
	}

	return 0;
}
