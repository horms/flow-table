/*
 * libflowtable: A user-space library for a Linux Kernel Flow API
 *
 * Copyright (C) 2015  Netronome.
 *
 * Contacts: Simon Horman <simon.horman@netronome.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <flow-table/data.h>

static bool
flow_table_field_header_match(const struct net_flow_field_ref *a,
			      const struct net_flow_field_ref *b)
{
	return a->header == b->header && a->field == b->field;
}

static bool
flow_table_field_ref_is_subset(const struct net_flow_field_ref *a,
			       const struct net_flow_field_ref *b)
{
	return (a->value_u64 & a->mask_u64 & b->mask_u64) ==
		(b->value_u64 & b->mask_u64);
}

/**
 * Evaluates if a is a subset of b taking account of masking
 * @a field references to compare
 * @b field references to compare
 *
 * @return true if a is a subset of b, false otherwise
 */
bool
flow_table_field_refs_are_subset(const struct net_flow_field_ref *a,
				 const struct net_flow_field_ref *b)
{
	int i;

	if (!a[0].header) {
		int j;

		for (j = 0; b[j].header; j++)
			if (b[j].mask_u64)
				return false;

		/* All of the field refs present in b have all-zero masks.
		 * a, which has no field refs present, is a subset of that.
		 */
		return true;
	}

	for (i = 0; a[i].header; i++) {
		int j;
		bool hit = false;
		bool found = false;

		for (j = 0; b[j].header; j++) {
			if (!flow_table_field_header_match(a + i, b + j))
				continue;
			found = true;
			hit = flow_table_field_ref_is_subset(a + i, b + j);
			if (hit)
				break;
		}

		/* No field ref present implies an field ref with
		 * an all-zeros mask. Which a[i] is a subset of.
		 * That is, a hit */
		if (!found)
			hit = true;

		if (hit)
			return true;
	}

	return false;
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

	for (i = 0; actions[i].uid; i++) {
		free(actions[i].name);
		free(actions[i].args);
	}

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
flow_table_rule_clone_data(struct net_flow_rule *dest,
			   const struct net_flow_rule *src)
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
