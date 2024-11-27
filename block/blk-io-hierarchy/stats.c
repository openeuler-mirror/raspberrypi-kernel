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
#include "../blk.h"
#include "../blk-mq-debugfs.h"

#define io_hierarchy_add(statsp, field, group, nr) \
	this_cpu_add((statsp)->field[group], nr)
#define io_hierarchy_inc(statsp, field, group) \
	io_hierarchy_add(statsp, field, group, 1)

void blk_mq_debugfs_register_hierarchy_stats(struct request_queue *q)
{
	struct blk_io_hierarchy_stats *stats;
	enum stage_group stage;

	lockdep_assert_held(&q->debugfs_mutex);

	stats = q->io_hierarchy_stats;
	if (!stats || !blk_mq_debugfs_enabled(q))
		return;

	stats->debugfs_dir = debugfs_create_dir("blk_io_hierarchy",
						q->debugfs_dir);

	for (stage = 0; stage < NR_STAGE_GROUPS; ++stage)
		blk_mq_debugfs_register_hierarchy(q, stage);
}

void blk_mq_debugfs_unregister_hierarchy_stats(struct request_queue *q)
{
	struct blk_io_hierarchy_stats *stats;
	enum stage_group stage;

	lockdep_assert_held(&q->debugfs_mutex);

	stats = q->io_hierarchy_stats;
	if (!stats || !blk_mq_debugfs_enabled(q))
		return;

	for (stage = 0; stage < NR_STAGE_GROUPS; ++stage)
		blk_mq_debugfs_unregister_hierarchy(q, stage);

	debugfs_remove_recursive(stats->debugfs_dir);
	stats->debugfs_dir = NULL;
}

int blk_io_hierarchy_stats_alloc(struct request_queue *q)
{
	struct blk_io_hierarchy_stats *stats;

	if (!queue_is_mq(q))
		return 0;

	stats = kzalloc(sizeof(struct blk_io_hierarchy_stats), GFP_KERNEL);
	if (!stats)
		return -ENOMEM;

	stats->q = q;
	q->io_hierarchy_stats = stats;

	return 0;
}

void blk_io_hierarchy_stats_free(struct request_queue *q)
{
	struct blk_io_hierarchy_stats *stats = q->io_hierarchy_stats;

	if (!stats)
		return;

	q->io_hierarchy_stats = NULL;
	kfree(stats);
}

bool blk_mq_hierarchy_registered(struct request_queue *q,
				 enum stage_group stage)
{
	struct blk_io_hierarchy_stats *stats = q->io_hierarchy_stats;

	if (!stats)
		return false;

	return stats->hstage[stage] != NULL;
}

void blk_mq_register_hierarchy(struct request_queue *q, enum stage_group stage)
{
	struct blk_io_hierarchy_stats *stats = q->io_hierarchy_stats;
	struct hierarchy_stage *hstage;

	if (!stats || !hierarchy_stage_name(stage))
		return;

	if (blk_mq_hierarchy_registered(q, stage)) {
		pr_warn("blk-io-hierarchy: disk %s is registering stage %s again.",
			q->disk->disk_name, hierarchy_stage_name(stage));
		return;
	}

	/*
	 * Alloc memory before freeze queue, prevent deadlock if new IO is
	 * issued by memory reclaim.
	 */
	hstage = kmalloc(sizeof(*hstage), GFP_KERNEL);
	if (!hstage)
		return;

	hstage->hstats = alloc_percpu(struct hierarchy_stats);
	if (!hstage->hstats) {
		kfree(hstage);
		return;
	}

	hstage->stage = stage;
	hstage->debugfs_dir = NULL;

	blk_mq_freeze_queue(q);
	blk_mq_quiesce_queue(q);

	mutex_lock(&q->debugfs_mutex);
	stats->hstage[stage] = hstage;
	blk_mq_debugfs_register_hierarchy(q, stage);
	mutex_unlock(&q->debugfs_mutex);

	blk_mq_unquiesce_queue(q);
	blk_mq_unfreeze_queue(q);
}

void blk_mq_unregister_hierarchy(struct request_queue *q,
				 enum stage_group stage)
{
	struct blk_io_hierarchy_stats *stats = q->io_hierarchy_stats;
	struct hierarchy_stage *hstage;

	if (!blk_mq_hierarchy_registered(q, stage))
		return;

	mutex_lock(&q->debugfs_mutex);

	blk_mq_debugfs_unregister_hierarchy(q, stage);

	hstage = stats->hstage[stage];
	stats->hstage[stage] = NULL;
	free_percpu(hstage->hstats);
	kfree(hstage);

	mutex_unlock(&q->debugfs_mutex);
}

static enum stat_group hierarchy_op(const struct bio *bio)
{
	if (op_is_discard(bio->bi_opf))
		return STAT_DISCARD;

	if (op_is_flush(bio->bi_opf) && !bio_sectors(bio))
		return STAT_FLUSH;

	if (op_is_write(bio->bi_opf))
		return STAT_WRITE;

	return STAT_READ;
}


void bio_hierarchy_start_io_acct(struct bio *bio, enum stage_group stage)
{
	struct request_queue *q = bio->bi_bdev->bd_queue;
	struct hierarchy_stage *hstage;

	if (!blk_mq_hierarchy_registered(q, stage))
		return;

	hstage = q->io_hierarchy_stats->hstage[stage];
	io_hierarchy_inc(hstage->hstats, dispatched, hierarchy_op(bio));
	bio->hierarchy_time = ktime_get_ns();
}

void bio_hierarchy_end_io_acct(struct bio *bio, enum stage_group stage,
			       u64 time)
{
	struct request_queue *q = bio->bi_bdev->bd_queue;
	struct hierarchy_stage *hstage;
	enum stat_group op;

	if (!blk_mq_hierarchy_registered(q, stage))
		return;

	op = hierarchy_op(bio);
	hstage = q->io_hierarchy_stats->hstage[stage];
	io_hierarchy_inc(hstage->hstats, completed, op);
	io_hierarchy_add(hstage->hstats, nsecs, op, time - bio->hierarchy_time);
}

void bio_list_hierarchy_end_io_acct(struct bio_list *list,
				    enum stage_group stage)
{
	u64 time = ktime_get_ns();
	struct bio *bio;

	bio_list_for_each(bio, list)
		bio_hierarchy_end_io_acct(bio, stage, time);
}
