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

static u64 threshold_value;
static int irqsoff_info_num = 3;
static int irqsoff_enable;

static DEFINE_PER_CPU(struct Irqsoff, irqsoff);
static DEFINE_PER_CPU(u64, irqsoff_off);

/* Per-cpu variable to prevent redundant calls when IRQs already off */
static DEFINE_PER_CPU(u64, irqsoff_flag);

void itrace_hardirqs_on(void)
{
	u64 diff;
	int front, cpu, num;
	char *caller;

	if (irqsoff_enable == IRQSOFF_OFF)
		return;

	if (this_cpu_read(irqsoff_flag)) {
		cpu = smp_processor_id();
		diff = sched_clock() - per_cpu(irqsoff_off, cpu);

		if (diff > threshold_value) {
			front = per_cpu(irqsoff, cpu).front;
			num = per_cpu(irqsoff, cpu).num + 1;
			caller = per_cpu(irqsoff, cpu).info[front].caller;

			per_cpu(irqsoff, cpu).info[front].t_max = diff;
			snprintf(caller, CALLER_FUNC_LEN, "%pS",
					__builtin_return_address(0));

			per_cpu(irqsoff, cpu).front = (front + 1) %
							irqsoff_info_num;
			per_cpu(irqsoff, cpu).num = num > irqsoff_info_num ?
						    irqsoff_info_num : num;
		}

		this_cpu_write(irqsoff_flag, 0);
	}
}
EXPORT_SYMBOL(itrace_hardirqs_on);

void itrace_hardirqs_off(void)
{
	if (irqsoff_enable == IRQSOFF_OFF)
		return;

	if (!this_cpu_read(irqsoff_flag)) {
		this_cpu_write(irqsoff_flag, 1);

		this_cpu_write(irqsoff_off, sched_clock());
	}
}
EXPORT_SYMBOL(itrace_hardirqs_off);

void itrace_hardirqs_ignore(void)
{
	if (irqsoff_enable == IRQSOFF_OFF)
		return;

	if (this_cpu_read(irqsoff_flag))
		this_cpu_write(irqsoff_flag, 0);
}
EXPORT_SYMBOL(itrace_hardirqs_ignore);

void itrace_irqsoff_set(u64 set)
{
	unsigned int i, j;
	int online_cpus = num_online_cpus();

	/* disable tracer and update threshold_value first */
	irqsoff_enable = IRQSOFF_OFF;
	threshold_value = set * NSEC_PER_USEC;

	for (i = 0; i < online_cpus; i++) {

		per_cpu(irqsoff, i).front = 0;
		per_cpu(irqsoff, i).num = 0;
		for (j = 0; j < IRQSOFF_INFO_NUM_MAX; j++) {
			per_cpu(irqsoff, i).info[j].t_max = 0;
			per_cpu(irqsoff, i).info[j].caller[0] = '\0';
		}

		/* enable tracer */
		if (set != 0) {
			per_cpu(irqsoff_flag, i) = 0;
			irqsoff_enable = IRQSOFF_ON;
		}
	}
}

void itrace_irqsoff_get(struct Irqsoff *is, int cpu)
{
	unsigned int j;
	char *caller;

	for (j = 0; j < irqsoff_info_num; j++) {
		caller = per_cpu(irqsoff, cpu).info[j].caller;

		is->num = per_cpu(irqsoff, cpu).num;
		is->info[j].t_max = per_cpu(irqsoff, cpu).info[j].t_max;
		strncpy(is->info[j].caller, caller, CALLER_FUNC_LEN);
	}
}

void itrace_irqsoff_num_set(int set)
{
	irqsoff_info_num = set;

	/* clear irqsoff.num while reset info_num */
	itrace_irqsoff_set(threshold_value / NSEC_PER_USEC);
}

int itrace_irqsoff_num_get(void)
{
	return irqsoff_info_num;
}
