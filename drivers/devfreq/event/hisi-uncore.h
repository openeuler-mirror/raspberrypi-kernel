/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * HiSilicon uncore devfreq event support
 *
 * Copyright (C) 2024 Hisilicon Limited
 * Author: Xiangwei Li <liwei728@hisilicon.com>
 *
 * This code is based on the uncore PMUs event.
 */
#ifndef __HISI_UNCORE_H__
#define __HISI_UNCORE_H__

#include <linux/device.h>
#include <linux/module.h>
#include <linux/perf_event.h>
#include <linux/types.h>

#define HISI_UNCORE_EVENT_NAME(name, type_name, package_id) ({ \
	int len; \
	len = sprintf(name, "uncore-%s-%d", type_name, package_id); \
	len; })

#define HISI_UNCORE_EVENT_TYPE_ATTR		  \
			DEVICE_ATTR_RW(hisi_uncore_event_types);

#define HISI_UNCORE_EVENT_CONFIG_ATTR		  \
			DEVICE_ATTR_RW(hisi_uncore_event_configs);

#define EVENT_TYPE_MAX_CNT			(20)
#define EVENT_TYPE_INVALID_VAL		(0xffff)
#define EVENT_CONFIG_MAX_CNT		(2)
#define EVENT_CONFIG_INVALID_VAL	(0xffff)

/*
 * The signle uncore pmu info.
 */
struct pmu_info {
	__u32 type;
	u64 load;
	int event_cnt;
	struct perf_event *event[EVENT_CONFIG_MAX_CNT];
};

/*
 * The uncore pmu controller can monitor device load by read PMU.
 */
struct hisi_uncore_event_info {
	char name[0x10];
	bool is_reset;
	int config_cnt;
	__u64 configs[EVENT_CONFIG_MAX_CNT];
	u64 max_load;
	struct device *dev;
	struct devfreq_event_dev *edev;
	struct devfreq_event_desc *desc;
	struct devfreq_perf_event *event;
	int related_pmu_cnt;
	struct pmu_info related_pmus[EVENT_TYPE_MAX_CNT];
	struct mutex lock;
};

ssize_t hisi_uncore_event_configs_show(struct device *dev,
				 struct device_attribute *attr, char *buf);
ssize_t hisi_uncore_event_configs_store(struct device *dev,
						 struct device_attribute *attr,
						 const char *buf, size_t count);

ssize_t hisi_uncore_event_types_show(struct device *dev,
				 struct device_attribute *attr, char *buf);
ssize_t hisi_uncore_event_types_store(struct device *dev,
						 struct device_attribute *attr,
						 const char *buf, size_t count);

void release_pmu_monitor(struct hisi_uncore_event_info *info);
u64 get_pmu_monitor_status(struct hisi_uncore_event_info *info);

#endif /* __HISI_UNCORE_PMU_H__ */
