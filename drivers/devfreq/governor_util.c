// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/drivers/devfreq/governor_util.c
 *
 *  Copyright (C) 2024 HISI UNCORE
 *	Xiangwei Li <liwei728@huawei.com>
 */

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/devfreq.h>
#include <linux/math64.h>
#include "governor.h"

/* Default constants for DevFreq-Util (DFUL) */
#define BW_UTIL_DEFAULT	(50)

static int devfreq_util_func(struct devfreq *df,
					unsigned long *freq)
{
	int err;
	struct devfreq_dev_status *stat;
	unsigned long cur_bw, max_bw;
	unsigned long cur_freq, step_freq;
	unsigned long min_freq, max_freq;
	unsigned int util, dful_val = BW_UTIL_DEFAULT;
	struct devfreq_util_data *data = df->data;

	err = devfreq_update_stats(df);
	if (err)
		return err;

	stat = &df->last_status;

	if (data) {
		dful_val = data->dful_val;
	}

	if (dful_val > 100)
		return -EINVAL;

	/* Assume MAX if it is going to be divided by zero */
	if (stat->total_time == 0) {
		*freq = df->scaling_max_freq;;
		return 0;
	}

	/* Prevent overflow */
	if (stat->busy_time >= (1 << 24) || stat->total_time >= (1 << 24)) {
		stat->busy_time >>= 7;
		stat->total_time >>= 7;
	}

	min_freq = df->scaling_min_freq;
	max_freq = df->scaling_max_freq;
	cur_freq = df->previous_freq;
	cur_bw = stat->busy_time;
	max_bw = stat->total_time;

	/* Set the desired frequency based on the load */
	util = div_u64(cur_bw * 100,
			 max_bw * div_u64(cur_freq * 100, max_freq) / 100);
	*freq = cur_freq * div_u64(util * 100, dful_val) / 100;

	step_freq = div_u64(max_freq - min_freq,
						 df->profile->max_state - 1);
	*freq = div_u64(*freq, step_freq) * step_freq;
	*freq = clamp(*freq, min_freq, max_freq);

	return 0;
}

static int devfreq_util_handler(struct devfreq *devfreq,
				unsigned int event, void *data)
{
	switch (event) {
	case DEVFREQ_GOV_START:
		devfreq_monitor_start(devfreq);
		break;

	case DEVFREQ_GOV_STOP:
		devfreq_monitor_stop(devfreq);
		break;

	case DEVFREQ_GOV_UPDATE_INTERVAL:
		devfreq_update_interval(devfreq, (unsigned int *)data);
		break;

	case DEVFREQ_GOV_SUSPEND:
		devfreq_monitor_suspend(devfreq);
		break;

	case DEVFREQ_GOV_RESUME:
		devfreq_monitor_resume(devfreq);
		break;

	default:
		break;
	}

	return 0;
}

static struct devfreq_governor devfreq_util = {
	.name = DEVFREQ_GOV_UTIL,
	.get_target_freq = devfreq_util_func,
	.event_handler = devfreq_util_handler,
};

static int __init devfreq_util_init(void)
{
	return devfreq_add_governor(&devfreq_util);
}
subsys_initcall(devfreq_util_init);

static void __exit devfreq_util_exit(void)
{
	int ret;

	ret = devfreq_remove_governor(&devfreq_util);
	if (ret)
		pr_err("%s: failed remove governor %d\n", __func__, ret);

	return;
}
module_exit(devfreq_util_exit);
MODULE_LICENSE("GPL");
