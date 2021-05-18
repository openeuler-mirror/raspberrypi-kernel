// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2021 Huawei Technologies Co., Ltd
 * Author: Bixuan Cui <cuibixuan@huawei.com>
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/sched/clock.h>
#include <linux/itrace.h>
#include <linux/time64.h>

static u64 threshold_value;
static int ihandler_info_num = 5;
static int ihandler_enable;

static DEFINE_PER_CPU(struct Ihandler, ihandler);
static DEFINE_PER_CPU(u64, ihandler_entry);

/* Per-cpu variable to prevent redundant calls when already entry handler */
static DEFINE_PER_CPU(int, ihandle_flag);

void itrace_ihandler_entry(void)
{
	if (ihandler_enable == IHANDLER_OFF)
		return;

	if (!this_cpu_read(ihandle_flag)) {
		this_cpu_write(ihandle_flag, 1);

		this_cpu_write(ihandler_entry, sched_clock());
	}
}

static void itrace_insert_diff(int cpu, u64 diff, int irq, const char *name)
{
	int j, index, find = 0;
	char *ihandler_name;
	unsigned int ct;
	u64 t_max;
	int front = per_cpu(ihandler, cpu).front;
	int num = per_cpu(ihandler, cpu).num;

	for (j = 0; j < num; j++) {
		index = (front + j) % num;
		if (per_cpu(ihandler, cpu).info[index].irq == irq) {
			find = 1;
			break;
		}
	}

	if (find != 0) {
		t_max = per_cpu(ihandler, cpu).info[index].t_max;
		ct = per_cpu(ihandler, cpu).info[index].ct + 1;

		per_cpu(ihandler, cpu).info[index].t_max = diff > t_max ?
							   diff : t_max;
		per_cpu(ihandler, cpu).info[index].ct = ct >
			IHANDLER_INFO_CT_MAX ? IHANDLER_INFO_CT_MAX : ct;
	} else {
		num = num + 1;
		ihandler_name = per_cpu(ihandler, cpu).info[front].name;

		per_cpu(ihandler, cpu).info[front].irq = irq;
		strncpy(ihandler_name, name, IRQ_NAME_LEN - 1);
		ihandler_name[IRQ_NAME_LEN - 1] = '\0';
		per_cpu(ihandler, cpu).info[front].t_max = diff;
		per_cpu(ihandler, cpu).front = (front + 1) %
					ihandler_info_num;
		per_cpu(ihandler, cpu).num = num > ihandler_info_num ?
					ihandler_info_num : num;
		per_cpu(ihandler, cpu).info[front].ct += 1;

	}
}

void itrace_ihandler_exit(int irq, const char *name)
{
	u64 diff;
	int cpu;

	if (ihandler_enable == IHANDLER_OFF)
		return;

	if (this_cpu_read(ihandle_flag)) {
		cpu = smp_processor_id();
		diff = sched_clock() - per_cpu(ihandler_entry, cpu);

		if (diff > threshold_value)
			itrace_insert_diff(cpu, diff, irq, name);

		this_cpu_write(ihandle_flag, 0);
	}
}

void itrace_ihandler_set(u64 set)
{
	unsigned int i, j;
	int online_cpus = num_online_cpus();

	/* disable tracer and update threshold_value first */
	ihandler_enable = IHANDLER_OFF;
	threshold_value = set * NSEC_PER_USEC;

	for (i = 0; i < online_cpus; i++) {

		per_cpu(ihandler, i).front = 0;
		per_cpu(ihandler, i).num = 0;
		for (j = 0; j < IHANDLER_INFO_NUM_MAX; j++) {
			per_cpu(ihandler, i).info[j].irq = 0;
			per_cpu(ihandler, i).info[j].name[0] = '\0';
			per_cpu(ihandler, i).info[j].t_max = 0;
			per_cpu(ihandler, i).info[j].ct = 0;
		}

		/* enable tracer */
		if (set != 0) {
			per_cpu(ihandle_flag, i) = 0;
			ihandler_enable = IHANDLER_ON;
		}
	}
}

void itrace_ihandler_get(struct Ihandler *ih, int cpu)
{
	unsigned int j;
	char *ihandler_name;

	for (j = 0; j < ihandler_info_num; j++) {
		ihandler_name = per_cpu(ihandler, cpu).info[j].name;

		ih->num = per_cpu(ihandler, cpu).num;
		ih->info[j].irq = per_cpu(ihandler, cpu).info[j].irq;
		strncpy(ih->info[j].name, ihandler_name, IRQ_NAME_LEN);
		ih->info[j].t_max = per_cpu(ihandler, cpu).info[j].t_max;
		ih->info[j].ct = per_cpu(ihandler, cpu).info[j].ct;
	}
}

void itrace_ihandler_num_set(int set)
{
	ihandler_info_num = set;

	/* clear ihandler of per cpu while reset info_num */
	itrace_ihandler_set(threshold_value / NSEC_PER_USEC);
}

int itrace_ihandler_num_get(void)
{
	return ihandler_info_num;
}
