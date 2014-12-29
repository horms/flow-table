#include <stdlib.h>

#include <flow-table/data.h>

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
