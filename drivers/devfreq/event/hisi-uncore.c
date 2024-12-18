// SPDX-License-Identifier: GPL-2.0-only
/*
 * HiSilicon uncore devfreq event support
 *
 * Copyright (C) 2024 Hisilicon Limited
 * Author: Xiangwei Li <liwei728@hisilicon.com>
 *
 * This code is based on the uncore PMUs event.
 */
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/ctype.h>
#include <linux/devfreq-event.h>

#include "hisi-uncore.h"

void release_pmu_monitor(struct hisi_uncore_event_info *info)
{
	int type_id, evt_id;
	struct pmu_info *pmu_info;

	mutex_lock(&info->lock);
	for (type_id = 0; type_id < info->related_pmu_cnt; ++type_id) {
		pmu_info = &info->related_pmus[type_id];
		for (evt_id = 0; evt_id < pmu_info->event_cnt; ++evt_id) {
			if (!pmu_info->event[evt_id])
				continue;
			perf_event_release_kernel(pmu_info->event[evt_id]);
			pmu_info->event[evt_id] = NULL;
		}
		pmu_info->event_cnt = 0;
	}
	mutex_unlock(&info->lock);
	if (devfreq_event_is_enabled(info->edev))
		devfreq_event_disable_edev(info->edev);
}
EXPORT_SYMBOL_GPL(release_pmu_monitor);

static int reset_pmu_monitor(struct hisi_uncore_event_info *info)
{
	int err;
	struct pmu_info *pmu_info;
	int type_id, cfg_id;
	struct perf_event_attr attr = {
		.size		= sizeof(struct perf_event_attr),
		.pinned		= 1,
		.disabled	= 0,
	};

	info->is_reset = true;

	if (info->config_cnt == 0 || info->related_pmu_cnt == 0)
		return 0;

	mutex_lock(&info->lock);
	for (type_id = 0; type_id < info->related_pmu_cnt; ++type_id) {
		pmu_info = &info->related_pmus[type_id];
		attr.type = pmu_info->type;
		for (cfg_id = 0; cfg_id < info->config_cnt; ++cfg_id) {
			attr.config = info->configs[cfg_id];
			pmu_info->event[cfg_id] = perf_event_create_kernel_counter(&attr,
						 smp_processor_id(), NULL, NULL, NULL);
			if (IS_ERR(pmu_info->event[cfg_id])) {
				err = PTR_ERR(pmu_info->event[cfg_id]);
				pmu_info->event[cfg_id] = NULL;
				release_pmu_monitor(info);
				info->related_pmu_cnt = 0;
				return err;
			}
			pmu_info->event_cnt++;
		}
	}
	mutex_unlock(&info->lock);

	if (!devfreq_event_is_enabled(info->edev))
		devfreq_event_enable_edev(info->edev);

	return 0;
}

u64 get_pmu_monitor_status(struct hisi_uncore_event_info *info)
{
	int t_id, c_id;
	u64 value, max_load;
	u64 enabled, running;
	struct pmu_info *pmu_info;

	max_load = 0;

	mutex_lock(&info->lock);
	for (t_id = 0; t_id < info->related_pmu_cnt; ++t_id) {
		pmu_info = &info->related_pmus[t_id];
		value = 0;
		for (c_id = 0; c_id < info->config_cnt; ++c_id) {
			if (!pmu_info->event[c_id]) {
				value = 0;
				break;
			}
			value += perf_event_read_value(pmu_info->event[c_id],
								 &enabled, &running);
		}

		max_load = max(max_load, value - pmu_info->load);
		pmu_info->load = value;
	}

	mutex_unlock(&info->lock);
	return max_load;
}
EXPORT_SYMBOL_GPL(get_pmu_monitor_status);

ssize_t hisi_uncore_event_configs_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	int i;
	struct hisi_uncore_event_info *info = dev_get_drvdata(dev->parent);

	for (i = 0; i < info->config_cnt; ++i)
		sprintf(buf, "%s %lld\n", buf, info->configs[i]);

	return sprintf(buf, "%s\n", buf);
}
EXPORT_SYMBOL_GPL(hisi_uncore_event_configs_show);

ssize_t hisi_uncore_event_configs_store(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t count)
{
	int err;
	char *item;
	u32 head, tail, cfg_cnt;
	struct hisi_uncore_event_info *info = dev_get_drvdata(dev->parent);

	if (!buf)
		return 0;

	release_pmu_monitor(info);

	head = 0;
	cfg_cnt = 0;
	item = kcalloc(count + 1, sizeof(*item), GFP_KERNEL);
	if (!item)
		return -ENOMEM;

	while (cfg_cnt < EVENT_CONFIG_MAX_CNT) {
		while (head < count && isspace(buf[head]))
			head++;

		if (!isalnum(buf[head]))
			break;

		tail = head + 1;
		while (tail < count && isalnum(buf[tail]))
			tail++;

		strncpy(item, buf + head, tail - head);
		item[tail - head] = '\0';
		head = tail;

		err = kstrtou64(item, 10, &info->configs[cfg_cnt]);
		if (err) {
			info->config_cnt = 0;
			return err;
		}

		cfg_cnt++;
	}

	info->config_cnt = cfg_cnt;
	kfree(item);

	err = reset_pmu_monitor(info);
	if (err)
		return err;

	return count;
}
EXPORT_SYMBOL_GPL(hisi_uncore_event_configs_store);

ssize_t hisi_uncore_event_types_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	int i;
	struct hisi_uncore_event_info *info = dev_get_drvdata(dev->parent);

	for (i = 0; i < info->related_pmu_cnt; ++i)
		sprintf(buf, "%s %d\n", buf, info->related_pmus[i].type);

	return sprintf(buf, "%s\n", buf);
}
EXPORT_SYMBOL_GPL(hisi_uncore_event_types_show);

ssize_t hisi_uncore_event_types_store(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t count)
{
	int err;
	char *item;
	u32 head, tail, type_cnt;
	struct hisi_uncore_event_info *info = dev_get_drvdata(dev->parent);

	if (!buf)
		return 0;

	release_pmu_monitor(info);

	head = 0;
	type_cnt = 0;
	item = kcalloc(count + 1, sizeof(*item), GFP_KERNEL);
	if (!item)
		return -ENOMEM;

	while (type_cnt < EVENT_TYPE_MAX_CNT) {
		while (head < count && isspace(buf[head]))
			head++;

		if (!isalnum(buf[head]))
			break;

		tail = head + 1;
		while (tail < count && isalnum(buf[tail]))
			tail++;

		strncpy(item, buf + head, tail - head);
		item[tail - head] = '\0';
		head = tail;

		err = kstrtou32(item, 10, &info->related_pmus[type_cnt].type);
		if (err) {
			info->related_pmu_cnt = 0;
			return err;
		}

		type_cnt++;
	}

	info->related_pmu_cnt = type_cnt;
	kfree(item);

	err = reset_pmu_monitor(info);
	if (err)
		return err;

	return count;
}
EXPORT_SYMBOL_GPL(hisi_uncore_event_types_store);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Xiangwei Li <liwei728@huawei.com>");
