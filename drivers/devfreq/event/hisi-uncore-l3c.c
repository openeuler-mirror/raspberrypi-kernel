// SPDX-License-Identifier: GPL-2.0-only
/*
 * hisi-uncore-l3c.c - Hisi uncore PMU (Platform Performance Monitoring Unit) support
 *
 * Copyright (c) 2024 Hisi Electronics Co., Ltd.
 * Author : Xiangwei Li <liwei728@huawei.com>
 *
 * This driver is based on drivers/devfreq/hisi_uncore/hisi-uncore-pmu.c
 */

#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/devfreq-event.h>

#include "hisi-uncore.h"

HISI_UNCORE_EVENT_TYPE_ATTR;
HISI_UNCORE_EVENT_CONFIG_ATTR;

static int l3c_get_events(struct devfreq_event_dev *edev, struct devfreq_event_data *edata)
{
	u64 load;
	struct hisi_uncore_event_info *info = devfreq_event_get_drvdata(edev);

	load = get_pmu_monitor_status(info);

	if (info->is_reset) {
		info->is_reset = false;
		info->max_load = 0;
		return 0;
	}

	info->max_load = max(info->max_load, load);
	edata->load_count = load;
	edata->total_count = info->max_load;

	return 0;
}

static int l3c_set_events(struct devfreq_event_dev *edev)
{
	return 0;
}

static const struct devfreq_event_ops l3c_event_ops = {
	.set_event = l3c_set_events,
	.get_event = l3c_get_events,
};

static int hisi_l3c_event_probe(struct platform_device *pdev)
{
	int ret;
	struct hisi_uncore_event_info *data;
	struct devfreq_event_dev *edev;
	struct devfreq_event_desc *desc;
	struct device *dev = &pdev->dev;

	data = devm_kzalloc(dev, sizeof(struct hisi_uncore_event_info), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->dev = dev;
	HISI_UNCORE_EVENT_NAME(data->name, "l3c", dev->id);

	desc = devm_kzalloc(dev, sizeof(*desc), GFP_KERNEL);
	if (!desc)
		return -ENOMEM;
	desc->ops = &l3c_event_ops;
	desc->driver_data = data;
	desc->name = data->name;
	data->desc = desc;

	edev = devm_devfreq_event_add_edev(dev, desc);
	if (IS_ERR(edev)) {
		dev_err(dev,
			"failed to add devfreq-event device\n");
		ret = PTR_ERR(edev);
		return ret;
	}

	data->edev = edev;

	ret = device_create_file(&edev->dev, &dev_attr_hisi_uncore_event_types);
	if (ret) {
		dev_err(&pdev->dev, "Failed to create custom sysfs files\n");
		return ret;
	}

	ret = device_create_file(&edev->dev, &dev_attr_hisi_uncore_event_configs);
	if (ret) {
		dev_err(&pdev->dev, "Failed to create custom sysfs files\n");
		return ret;
	}

	platform_set_drvdata(pdev, data);

	mutex_init(&data->lock);

	return 0;
}

static int hisi_l3c_event_remove(struct platform_device *pdev)
{
	struct hisi_uncore_event_info *data = platform_get_drvdata(pdev);

	release_pmu_monitor(data);
	device_remove_file(&data->edev->dev, &dev_attr_hisi_uncore_event_types);
	device_remove_file(&data->edev->dev, &dev_attr_hisi_uncore_event_configs);

	return 0;
}

static const struct platform_device_id hisi_l3c_pmu_plat_match[] = {
	{ .name = "EVT-UNCORE-L3C", },
	{}
};
MODULE_DEVICE_TABLE(platform, hisi_l3c_pmu_plat_match);

struct platform_driver hisi_l3c_event_driver = {
	.probe	= hisi_l3c_event_probe,
	.remove	= hisi_l3c_event_remove,
	.driver = {
		.name   = "EVT-UNCORE-L3C",
	},
	.id_table = hisi_l3c_pmu_plat_match,
};

module_platform_driver(hisi_l3c_event_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Xiangwei Li <liwei728@huawei.com>");
MODULE_DESCRIPTION("Hisi uncore l3c pmu events driver");
