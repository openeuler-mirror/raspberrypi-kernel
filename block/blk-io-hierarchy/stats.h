/* SPDX-License-Identifier: GPL-2.0 */
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

#ifndef BLK_IO_HIERARCHY_STATS_H
#define BLK_IO_HIERARCHY_STATS_H

#ifdef CONFIG_BLK_IO_HIERARCHY_STATS

#include <linux/blkdev.h>
#include "../blk-mq-debugfs.h"

struct bio_hierarchy_data {
	u64 time;
};

struct hierarchy_stats {
	u64 nsecs[NR_STAT_GROUPS];
	unsigned long dispatched[NR_STAT_GROUPS];
	unsigned long completed[NR_STAT_GROUPS];
};

struct hierarchy_stage {
	enum stage_group stage;
	struct dentry *debugfs_dir;
	struct hierarchy_stats __percpu *hstats;
};

struct blk_io_hierarchy_stats {
	struct request_queue *q;
	struct dentry *debugfs_dir;
	struct hierarchy_stage *hstage[NR_STAGE_GROUPS];
};

const char *hierarchy_stage_name(enum stage_group stage);
int blk_io_hierarchy_stats_alloc(struct request_queue *q);
void blk_io_hierarchy_stats_free(struct request_queue *q);

/* APIs for stage registration */
bool blk_mq_hierarchy_registered(struct request_queue *q,
				 enum stage_group stage);
void blk_mq_register_hierarchy(struct request_queue *q, enum stage_group stage);
void blk_mq_unregister_hierarchy(struct request_queue *q,
				 enum stage_group stage);

/* APIs for disk level debugfs */
void blk_mq_debugfs_register_hierarchy_stats(struct request_queue *q);
void blk_mq_debugfs_unregister_hierarchy_stats(struct request_queue *q);

/* APIs for stage level debugfs */
void blk_mq_debugfs_register_hierarchy(struct request_queue *q,
				       enum stage_group stage);
void blk_mq_debugfs_unregister_hierarchy(struct request_queue *q,
					 enum stage_group stage);

/* APIs for bio based stage io accounting */
void bio_hierarchy_start_io_acct(struct bio *bio, enum stage_group stage);
void bio_hierarchy_end_io_acct(struct bio *bio, enum stage_group stage,
			       u64 time);
void bio_list_hierarchy_end_io_acct(struct bio_list *list,
				    enum stage_group stage);
#else /* CONFIG_BLK_IO_HIERARCHY_STATS */

static inline int
blk_io_hierarchy_stats_alloc(struct request_queue *q)
{
	return 0;
}

static inline void
blk_io_hierarchy_stats_free(struct request_queue *q)
{
}

static inline bool
blk_mq_hierarchy_registered(struct request_queue *q, enum stage_group stage)
{
	return false;
}

static inline void
blk_mq_register_hierarchy(struct request_queue *q, enum stage_group stage)
{
}

static inline void
blk_mq_unregister_hierarchy(struct request_queue *q, enum stage_group stage)
{
}

static inline void
blk_mq_debugfs_register_hierarchy_stats(struct request_queue *q)
{
}

static inline void
blk_mq_debugfs_unregister_hierarchy_stats(struct request_queue *q)
{
}

static inline void
blk_mq_debugfs_register_hierarchy(struct request_queue *q,
				  enum stage_group stage)
{
}

static inline void
blk_mq_debugfs_unregister_hierarchy(struct request_queue *q,
				    enum stage_group stage)
{
}

static inline void
bio_hierarchy_start_io_acct(struct bio *bio, enum stage_group stage)
{
}

static inline void
bio_hierarchy_end_io_acct(struct bio *bio, enum stage_group stage, u64 time)
{
}

static inline void
bio_list_hierarchy_end_io_acct(struct bio_list *list, enum stage_group stage)
{
}
#endif /* CONFIG_BLK_IO_HIERARCHY_STATS */
#endif /* BLK_IO_HIERARCHY_STATS_H */
