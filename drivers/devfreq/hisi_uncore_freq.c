// SPDX-License-Identifier: GPL-2.0-only
/*
 * HiSilicon uncore frequency scaling driver
 *
 * Copyright (c) 2024 HiSilicon Co., Ltd
 * Author : Jie Zhan <zhanjie9@hisilicon.com>
 */

#include <linux/acpi.h>
#include <linux/devfreq.h>
#include <linux/device.h>
#include <linux/dev_printk.h>
#include <linux/errno.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/mailbox_client.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/platform_device.h>
#include <linux/pm_opp.h>
#include <linux/property.h>
#include <linux/topology.h>
#include <linux/devfreq-event.h>

#include <acpi/pcc.h>

#define HZ_PER_MHZ	1000000

/* Don't care OPP votlage, take 1V as default */
#define DEF_OPP_VOLT_UV	1000000

#define RELATED_EVENT_MAX_CNT	4
#define RELATED_EVENT_NAME_LEN	10

struct related_event {
	char name[RELATED_EVENT_NAME_LEN];
	struct platform_device *pdev;
	struct devfreq_event_dev *edev;
};

struct hisi_uncore_freq {
	struct device *dev;
	struct mbox_client cl;
	struct pcc_mbox_chan *pchan;
	void __iomem *pcc_shmem_addr;
	int chan_id;
	unsigned long freq_min;
	unsigned long freq_max;
	unsigned long freq_step;
	struct devfreq *devfreq;
	int related_package;
	struct cpumask related_cpus;
	int related_event_cnt;
	struct related_event related_events[RELATED_EVENT_MAX_CNT];
};

struct hisi_uncore_pcc_data {
	u16 status;
	u16 resv;
	u32 data;
};

struct hisi_uncore_pcc_shmem {
	struct acpi_pcct_shared_memory head;
	struct hisi_uncore_pcc_data pcc_data;
};

enum hisi_uncore_pcc_cmd_type {
	HUCF_PCC_CMD_GET_CAP = 0,
	HUCF_PCC_CMD_GET_FREQ,
	HUCF_PCC_CMD_SET_FREQ,
	HUCF_PCC_CMD_GET_MODE,
	HUCF_PCC_CMD_SET_MODE,
	HUCF_PCC_CMD_GET_PLAT_FREQ_MIN,
	HUCF_PCC_CMD_GET_PLAT_FREQ_MAX,
	HUCF_PCC_CMD_GET_PLAT_FREQ_STEP,
	HUCF_PCC_CMD_MAX = 256,
};

enum hisi_uncore_freq_mode {
	HUCF_MODE_PLATFORM = 0,
	HUCF_MODE_OS,
};

/* Timeout = PCC nominal latency * NUM */
#define HUCF_PCC_POLL_TIMEOUT_NUM	1000
#define HUCF_PCC_POLL_INTERVAL_US	5

static int hisi_uncore_request_pcc_chan(struct hisi_uncore_freq *uncore)
{
	struct pcc_mbox_chan *pcc_chan;
	int rc;

	uncore->cl = (struct mbox_client) {
		.dev = uncore->dev,
		.tx_block = false,
		.knows_txdone = true,
	};

	pcc_chan = pcc_mbox_request_channel(&uncore->cl, uncore->chan_id);
	if (IS_ERR(pcc_chan)) {
		dev_err(uncore->dev, "Failed to request PCC channel %u\n",
			uncore->chan_id);
		return -ENODEV;
	}

	uncore->pchan = pcc_chan;
	if (!pcc_chan->shmem_base_addr) {
		dev_err(uncore->dev, "Invalid PCC shared memory address\n");
		rc = -EINVAL;
		goto err_pcc_chan_free;
	}

	if (pcc_chan->shmem_size < sizeof(struct hisi_uncore_pcc_shmem)) {
		dev_err(uncore->dev, "Invalid PCC shared memory size (%lluB)\n",
			pcc_chan->shmem_size);
		rc = -EINVAL;
		goto err_pcc_chan_free;
	}

	uncore->pcc_shmem_addr = ioremap(pcc_chan->shmem_base_addr,
					 pcc_chan->shmem_size);
	if (!uncore->pcc_shmem_addr) {
		rc = -ENOMEM;
		goto err_pcc_chan_free;
	}

	return 0;

err_pcc_chan_free:
	pcc_mbox_free_channel(uncore->pchan);
	return rc;
}

static void hisi_uncore_free_pcc_chan(struct hisi_uncore_freq *uncore)
{
	if (uncore->pchan)
		pcc_mbox_free_channel(uncore->pchan);
}

static acpi_status hisi_uncore_pcc_reg_scan(struct acpi_resource *res,
					    void *ctx)
{
	struct acpi_resource_generic_register *reg;
	struct hisi_uncore_freq *uncore;

	if (!res || res->type != ACPI_RESOURCE_TYPE_GENERIC_REGISTER)
		return AE_OK;

	reg = &res->data.generic_reg;
	if (reg->space_id != ACPI_ADR_SPACE_PLATFORM_COMM)
		return AE_OK;

	/* PCC subspace ID stored in Access Size */
	uncore = ctx;
	uncore->chan_id = reg->access_size;
	return AE_CTRL_TERMINATE;
}

static int hisi_uncore_init_pcc_chan(struct hisi_uncore_freq *uncore)
{
	acpi_handle handle = ACPI_HANDLE(uncore->dev);
	acpi_status status;

	uncore->chan_id = -1;
	status = acpi_walk_resources(handle, METHOD_NAME__CRS,
				     hisi_uncore_pcc_reg_scan, uncore);
	if (ACPI_FAILURE(status) || uncore->chan_id < 0) {
		dev_err(uncore->dev, "Failed to get a PCC channel\n");
		return -ENODEV;
	}

	return hisi_uncore_request_pcc_chan(uncore);
}

static int hisi_uncore_cmd_send(struct hisi_uncore_freq *uncore,
				u8 cmd, u32 *data)
{
	struct hisi_uncore_pcc_shmem __iomem *addr = uncore->pcc_shmem_addr;
	struct pcc_mbox_chan *pchan = uncore->pchan;
	struct hisi_uncore_pcc_shmem shmem;
	u16 status;
	int rc;

	/* Copy data */
	shmem.head = (struct acpi_pcct_shared_memory) {
		.signature = PCC_SIGNATURE | uncore->chan_id,
		.command = cmd,
		.status = 0,
	};
	shmem.pcc_data.data = *data;
	memcpy_toio(addr, &shmem, sizeof(shmem));

	/* Ring doorbell */
	rc = mbox_send_message(pchan->mchan, &cmd);
	if (rc < 0) {
		dev_err(uncore->dev, "Failed to send mbox message, %d\n", rc);
		return rc;
	}

	/* Wait status */
	rc = readw_poll_timeout(&addr->head.status, status,
				status & (PCC_STATUS_CMD_COMPLETE ||
					  PCC_STATUS_ERROR),
				HUCF_PCC_POLL_INTERVAL_US,
				pchan->latency * HUCF_PCC_POLL_TIMEOUT_NUM);
	if (rc) {
		dev_err(uncore->dev, "PCC channel response timeout\n");
		return -ETIME;
	}

	if (status & PCC_STATUS_ERROR) {
		dev_err(uncore->dev, "PCC cmd error\n");
		return -EIO;
	}

	/* Success, copy data back */
	memcpy_fromio(data, &addr->pcc_data.data, sizeof(*data));

	mbox_client_txdone(pchan->mchan, 0);
	return rc;
}

static int hisi_uncore_target(struct device *dev, unsigned long *freq,
			      u32 flags)
{
	struct hisi_uncore_freq *uncore = dev_get_drvdata(dev);
	u32 data = *freq / HZ_PER_MHZ;

	if (flags & DEVFREQ_FLAG_LEAST_UPPER_BOUND)
		data = roundup(data, uncore->freq_step);
	else
		data = rounddown(data, uncore->freq_step);

	data = clamp((unsigned long)data, uncore->freq_min, uncore->freq_max);

	return hisi_uncore_cmd_send(uncore, HUCF_PCC_CMD_SET_FREQ, &data);
}

static int hisi_uncore_get_dev_status(struct device *dev,
				      struct devfreq_dev_status *stat)
{
	int rc, i, ratio;
	struct related_event *event;
	struct devfreq_event_data edata;
	struct hisi_uncore_freq *uncore = dev_get_drvdata(dev);

	ratio = 0;
	for (i = 0; i < uncore->related_event_cnt; ++i) {
		event = &uncore->related_events[i];
		event->edev = devfreq_event_get_edev_by_dev(&event->pdev->dev);
		if (!event->edev)
			continue;
		rc = devfreq_event_get_event(event->edev, &edata);
		if (rc)
			return rc;

		if (edata.load_count == edata.total_count) {
			stat->busy_time = edata.load_count;
			stat->total_time = edata.total_count;
			return 0;
		}

		if (ratio <= edata.load_count * 100 / edata.total_count) {
			stat->busy_time = edata.load_count;
			stat->total_time = edata.total_count;
			ratio = edata.load_count * 100 / edata.total_count;
		}
	}

	return 0;
}

static int hisi_uncore_get_cur_freq(struct device *dev, unsigned long *freq)
{
	struct hisi_uncore_freq *uncore = dev_get_drvdata(dev);
	u32 data;
	int rc;

	rc = hisi_uncore_cmd_send(uncore, HUCF_PCC_CMD_GET_FREQ, &data);
	*freq = data * HZ_PER_MHZ;

	return rc;
}

static int hisi_uncore_add_opp(struct hisi_uncore_freq *uncore)
{
	unsigned long freq_mhz;
	u32 data;
	int rc;

	rc = hisi_uncore_cmd_send(uncore, HUCF_PCC_CMD_GET_PLAT_FREQ_MIN, &data);
	if (rc)
		return rc;
	uncore->freq_min = data;

	rc = hisi_uncore_cmd_send(uncore, HUCF_PCC_CMD_GET_PLAT_FREQ_MAX, &data);
	if (rc)
		return rc;
	uncore->freq_max = data;

	rc = hisi_uncore_cmd_send(uncore, HUCF_PCC_CMD_GET_PLAT_FREQ_STEP, &data);
	if (rc)
		return rc;
	uncore->freq_step = data;

	for (freq_mhz = uncore->freq_min; freq_mhz <= uncore->freq_max;
	     freq_mhz += uncore->freq_step) {
		rc = dev_pm_opp_add(uncore->dev, freq_mhz * HZ_PER_MHZ, DEF_OPP_VOLT_UV);
		if (rc) {
			unsigned long freq_curr = freq_mhz;
			dev_err(uncore->dev, "Add OPP %lu failed (%d)\n",
				freq_mhz, rc);
			for (freq_mhz = uncore->freq_min; freq_mhz < freq_curr;
			     freq_mhz += uncore->freq_step)
				dev_pm_opp_remove(uncore->dev,
						  freq_mhz * HZ_PER_MHZ);
			break;
		}
	}

	return rc;
}

static void hisi_uncore_remove_opp(struct hisi_uncore_freq *uncore)
{
	unsigned long freq_mhz;

	for (freq_mhz = uncore->freq_min; freq_mhz <= uncore->freq_max;
	     freq_mhz += uncore->freq_step)
		dev_pm_opp_remove(uncore->dev, freq_mhz * HZ_PER_MHZ);
}

static int hisi_uncore_devfreq_register(struct hisi_uncore_freq *uncore)
{
	struct devfreq_dev_profile *profile;
	u32 data;

	data = HUCF_MODE_OS;
	hisi_uncore_cmd_send(uncore, HUCF_PCC_CMD_SET_MODE, &data);
	msleep(200);
	hisi_uncore_cmd_send(uncore, HUCF_PCC_CMD_GET_FREQ, &data);
	dev_info(uncore->dev, "init freq %u\n", data);

	profile = devm_kzalloc(uncore->dev, sizeof(*profile), GFP_KERNEL);
	if (!profile)
		return -ENOMEM;

	profile->initial_freq = (unsigned long)data * HZ_PER_MHZ;
	profile->polling_ms = 1000;
	profile->timer = DEVFREQ_TIMER_DELAYED;
	profile->target = hisi_uncore_target;
	profile->get_dev_status = hisi_uncore_get_dev_status;
	profile->get_cur_freq = hisi_uncore_get_cur_freq;

	uncore->devfreq = devm_devfreq_add_device(uncore->dev, profile,
						  DEVFREQ_GOV_USERSPACE, NULL);
	if (IS_ERR(uncore->devfreq)) {
		dev_err(uncore->dev, "Failed to add devfreq device\n");
		return PTR_ERR(uncore->devfreq);
	}

	return 0;
}

static int hisi_uncore_mark_related_cpus(struct hisi_uncore_freq *uncore,
					 char *property,
					 int (get_topo_id)(int cpu),
					 struct cpumask *(get_cpumask)(int cpu))
{
	unsigned int i, cpu;
	size_t len;
	u32 *num;
	int rc;

	rc = device_property_count_u32(uncore->dev, property);
	if (rc < 0)
		return rc;

	len = rc;
	num = kcalloc(len, sizeof(*num), GFP_KERNEL);
	if (!num)
		return -ENOMEM;

	rc = device_property_read_u32_array(uncore->dev, property, num, len);
	if (rc)
		goto out;

	for (i = 0; i < len; i++) {
		for_each_possible_cpu(cpu) {
			if (get_topo_id(cpu) == num[i]) {
				cpumask_or(&uncore->related_cpus,
					   &uncore->related_cpus,
					   get_cpumask(cpu));
				break;
			}
		}
	}

out:
	kfree(num);
	return rc;

}

static int get_package_id(int cpu)
{
	return topology_physical_package_id(cpu);
}

static struct cpumask *get_package_cpumask(int cpu)
{
	return topology_core_cpumask(cpu);
}

static int get_cluster_id(int cpu)
{
	return topology_cluster_id(cpu);
}

static struct cpumask *get_cluster_cpumask(int cpu)
{
	return topology_cluster_cpumask(cpu);
}

static int hisi_uncore_mark_related_cpus_wrap(struct hisi_uncore_freq *uncore)
{
	int rc;

	cpumask_clear(&uncore->related_cpus);

	rc = hisi_uncore_mark_related_cpus(uncore, "related-package",
					   get_package_id,
					   get_package_cpumask);
	if (rc == 0)
		return rc;

	rc = hisi_uncore_mark_related_cpus(uncore, "related-cluster",
					   get_cluster_id,
					   get_cluster_cpumask);
	return rc;
}

static ssize_t related_cpus_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct platform_device *pdev = to_platform_device(dev->parent);
	struct hisi_uncore_freq *uncore = platform_get_drvdata(pdev);

	return cpumap_print_to_pagebuf(true, buf, &uncore->related_cpus);
}
DEVICE_ATTR_RO(related_cpus);

static int get_related_package(struct hisi_uncore_freq *uncore)
{
	int rc;

	rc = device_property_read_u32(uncore->dev, "related-package",
									 &uncore->related_package);
	if (rc) {
		dev_err(uncore->dev, "failed to read related-package property\n");
		return rc;
	}

	return 0;
}

static ssize_t related_package_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct platform_device *pdev = to_platform_device(dev->parent);
	struct hisi_uncore_freq *uncore = platform_get_drvdata(pdev);

	return sprintf(buf, "%u\n", uncore->related_package);
}
DEVICE_ATTR_RO(related_package);

static int creat_related_event(struct hisi_uncore_freq *uncore, char *name)
{
	int evt_id;
	struct related_event *event;
	char dev_name[RELATED_EVENT_NAME_LEN + 10];

	evt_id = uncore->related_event_cnt;
	event = &uncore->related_events[evt_id];

	sprintf(dev_name, "%s-%s", "EVT-UNCORE", name);
	event->pdev = platform_device_register_data(
					 uncore->dev,
					 dev_name,
					 uncore->related_package,
					 NULL,
					 0);
	if (IS_ERR(event->pdev))
			return PTR_ERR(event->pdev);

	strncpy(event->name, name, strlen(name));

	return 0;
}

static void remove_related_event(struct hisi_uncore_freq *uncore)
{
	int i;
	struct related_event *event;

	devfreq_suspend_device(uncore->devfreq);
	for (i = 0; i < uncore->related_event_cnt; ++i) {
		event = &uncore->related_events[i];
		event->edev = NULL;
		memset(event->name, 0, RELATED_EVENT_NAME_LEN);
		platform_device_unregister(event->pdev);
	}

	uncore->related_event_cnt = 0;

	return;
}

static ssize_t related_events_store(struct device *dev,
						 struct device_attribute *attr,
						 const char *buf, size_t count)
{
	int err;
	char *item;
	u32 head, tail;
	struct platform_device *pdev = to_platform_device(dev->parent);
	struct hisi_uncore_freq *uncore = platform_get_drvdata(pdev);

	if (!buf)
		return 0;

	remove_related_event(uncore);

	head = 0;
	item = kcalloc(count + 1, sizeof(*item), GFP_KERNEL);
	if (!item)
		return -ENOMEM;

	while (uncore->related_event_cnt < RELATED_EVENT_MAX_CNT) {
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

		err = creat_related_event(uncore, item);
		if (err) {
			kfree(item);
			return err;
		}
		uncore->related_event_cnt++;
	}

	devfreq_resume_device(uncore->devfreq);

	kfree(item);
	return count;
}

static ssize_t related_events_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	int evt_id;
	struct platform_device *pdev = to_platform_device(dev->parent);
	struct hisi_uncore_freq *uncore = platform_get_drvdata(pdev);

	for (evt_id = 0; evt_id < uncore->related_event_cnt; ++evt_id) {
		sprintf(buf, "%s %s", buf, uncore->related_events[evt_id].name);
	}
	return sprintf(buf, "%s\n", buf);
}
DEVICE_ATTR_RW(related_events);

static int hisi_uncore_probe(struct platform_device *pdev)
{
	struct hisi_uncore_freq *uncore;
	int rc;

	uncore = devm_kzalloc(&pdev->dev, sizeof(*uncore), GFP_KERNEL);
	if (!uncore)
		return -ENOMEM;

	uncore->dev = &pdev->dev;
	platform_set_drvdata(pdev, uncore);

	rc = hisi_uncore_init_pcc_chan(uncore);
	if (rc) {
		dev_err(&pdev->dev, "PCC channel init failed %d", rc);
		return rc;
	}

	rc = hisi_uncore_add_opp(uncore);
	if (rc) {
		dev_err(&pdev->dev, "Register freq failed (%d)\n", rc);
		goto err_free_pcc;
	}

	rc = hisi_uncore_devfreq_register(uncore);
	if (rc) {
		dev_err(&pdev->dev, "Failed to register devfreq (%d)\n", rc);
		goto err_free_opp;
	}

	rc = get_related_package(uncore);
	if (rc)
		goto err_free_opp;

	hisi_uncore_mark_related_cpus_wrap(uncore);

	rc = device_create_file(&uncore->devfreq->dev, &dev_attr_related_cpus);
	if (rc) {
		dev_err(&pdev->dev, "Failed to create custom sysfs files\n");
		goto err_free_opp;
	}

	rc = device_create_file(&uncore->devfreq->dev, &dev_attr_related_package);
	if (rc) {
		dev_err(&pdev->dev, "Failed to create custom sysfs files\n");
		goto err_free_opp;
	}

	rc = device_create_file(&uncore->devfreq->dev, &dev_attr_related_events);
	if (rc) {
		dev_err(&pdev->dev, "Failed to create custom sysfs files\n");
		goto err_free_opp;
	}

	return 0;

err_free_opp:
	hisi_uncore_remove_opp(uncore);
err_free_pcc:
	hisi_uncore_free_pcc_chan(uncore);

	return rc;
}

static int hisi_uncore_remove(struct platform_device *pdev)
{
	struct hisi_uncore_freq *uncore = platform_get_drvdata(pdev);
	u32 data = HUCF_MODE_PLATFORM;
	hisi_uncore_cmd_send(uncore, HUCF_PCC_CMD_SET_MODE, &data);

	hisi_uncore_remove_opp(uncore);
	hisi_uncore_free_pcc_chan(uncore);
	remove_related_event(uncore);
	device_remove_file(&uncore->devfreq->dev, &dev_attr_related_cpus);
	device_remove_file(&uncore->devfreq->dev, &dev_attr_related_package);

	return 0;
}

static const struct acpi_device_id hisi_uncore_acpi_match[] = {
	{ "HISI04F1", },
	{ },
};
MODULE_DEVICE_TABLE(acpi, hisi_uncore_acpi_match);

static struct platform_driver hisi_uncore_platdrv = {
	.probe	= hisi_uncore_probe,
	.remove = hisi_uncore_remove,
	.driver = {
		.name	= "hisi_uncore_freq",
		.acpi_match_table = hisi_uncore_acpi_match,
	},
};
module_platform_driver(hisi_uncore_platdrv);

MODULE_DESCRIPTION("HiSilicon uncore frequency scaling driver");
MODULE_AUTHOR("Jie Zhan <zhanjie9@hisilicon.com>");
MODULE_LICENSE("GPL v2");
