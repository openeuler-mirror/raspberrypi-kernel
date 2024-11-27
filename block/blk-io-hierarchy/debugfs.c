// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023. Huawei Technologies Co., Ltd. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <linux/debugfs.h>

#include "stats.h"

static const char *stage_name[NR_STAGE_GROUPS] = {
#ifdef CONFIG_HIERARCHY_THROTTLE
	[STAGE_THROTTLE]	= "throtl",
#endif
};

const char *hierarchy_stage_name(enum stage_group stage)
{
	return stage_name[stage];
}

static int hierarchy_stats_show(void *data, struct seq_file *m)
{
	struct hierarchy_stage *hstage = data;
	int cpu;
	u64 dispatched[NR_STAT_GROUPS] = {0};
	u64 completed[NR_STAT_GROUPS] = {0};
	u64 latency[NR_STAT_GROUPS] = {0};

	for_each_possible_cpu(cpu) {
		int i;
		struct hierarchy_stats *stat = per_cpu_ptr(hstage->hstats, cpu);

		for (i = 0; i < NR_STAT_GROUPS; ++i) {
			dispatched[i] += stat->dispatched[i];
			completed[i] += stat->completed[i];
			latency[i] += stat->nsecs[i];
		}
	}

	seq_printf(m, "%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu\n",
		   dispatched[STAT_READ], completed[STAT_READ],
		   latency[STAT_READ], dispatched[STAT_WRITE],
		   completed[STAT_WRITE], latency[STAT_WRITE],
		   dispatched[STAT_DISCARD], completed[STAT_DISCARD],
		   latency[STAT_DISCARD], dispatched[STAT_FLUSH],
		   completed[STAT_FLUSH], latency[STAT_FLUSH]);

	return 0;
}

static struct blk_mq_debugfs_attr hierarchy_debugfs_attrs[] = {
	{"stats", 0400, hierarchy_stats_show},
	{},
};

static void hierarchy_register_stage(struct blk_io_hierarchy_stats *stats,
				     enum stage_group stage)
{
	struct hierarchy_stage *hstage = stats->hstage[stage];
	struct dentry *dir;

	if (!stage_name[stage] || hstage->debugfs_dir)
		return;

	dir = debugfs_create_dir(stage_name[stage], stats->debugfs_dir);
	if (IS_ERR(dir))
		return;

	hstage->debugfs_dir = dir;
	debugfs_create_files(dir, hstage, hierarchy_debugfs_attrs);
}

static void hierarchy_unregister_stage(struct blk_io_hierarchy_stats *stats,
				       enum stage_group stage)
{
	struct hierarchy_stage *hstage = stats->hstage[stage];

	if (!stage_name[stage] || !hstage->debugfs_dir)
		return;

	debugfs_remove_recursive(hstage->debugfs_dir);
	hstage->debugfs_dir = NULL;
}

void blk_mq_debugfs_register_hierarchy(struct request_queue *q,
				       enum stage_group stage)
{
	struct blk_io_hierarchy_stats *stats = q->io_hierarchy_stats;

	lockdep_assert_held(&q->debugfs_mutex);

	if (!blk_mq_hierarchy_registered(q, stage) ||
	    !blk_mq_debugfs_enabled(q))
		return;

	hierarchy_register_stage(stats, stage);
}

void blk_mq_debugfs_unregister_hierarchy(struct request_queue *q,
					 enum stage_group stage)
{
	struct blk_io_hierarchy_stats *stats = q->io_hierarchy_stats;

	lockdep_assert_held(&q->debugfs_mutex);

	if (!blk_mq_hierarchy_registered(q, stage) ||
	    !blk_mq_debugfs_enabled(q))
		return;

	hierarchy_unregister_stage(stats, stage);
}
