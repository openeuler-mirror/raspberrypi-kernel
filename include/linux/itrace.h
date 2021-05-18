/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2021 Huawei Technologies Co., Ltd
 * Author: Bixuan Cui <cuibixuan@huawei.com>
 */

#ifndef __LINUX_ITRACE_H
#define __LINUX_ITRACE_H

#define IRQ_NAME_LEN 20
#define IHANDLER_INFO_NUM_MIN 1
#define IHANDLER_INFO_NUM_MAX 30
#define IHANDLER_INFO_CT_MAX 99999
#define IHANDLER_THRESHOLD_MAX 10000000
#define IHANDLER_OFF 0
#define IHANDLER_ON 1

#define CALLER_FUNC_LEN 50
#define IRQSOFF_INFO_NUM_MIN 1
#define IRQSOFF_INFO_NUM_MAX 30
#define IRQSOFF_THRESHOLD_MAX 10000000
#define IRQSOFF_OFF 0
#define IRQSOFF_ON 1

struct irq_handler_info {
	int irq;
	char name[IRQ_NAME_LEN];
	u64 t_max;
	unsigned int ct;
};

struct Ihandler {
	int front;
	int num;
	struct irq_handler_info info[IHANDLER_INFO_NUM_MAX];
};

struct irqsoff_info {
	u64 t_max;
	char caller[CALLER_FUNC_LEN];
};

struct Irqsoff {
	int front;
	int num;
	struct irqsoff_info info[IRQSOFF_INFO_NUM_MAX];
};

#ifdef CONFIG_ITRACE_IHANDLER
extern void itrace_ihandler_entry(void);
extern void itrace_ihandler_exit(int irq, const char *name);
extern void itrace_ihandler_set(u64 set);
extern void itrace_ihandler_get(struct Ihandler *ih, int cpu);
extern void itrace_ihandler_num_set(int set);
extern int itrace_ihandler_num_get(void);
#else
static inline void __maybe_unused itrace_ihandler_entry(void)
{
};
static inline void __maybe_unused itrace_ihandler_exit(int irq, const char *name)
{
};
#endif /* CONFIG_ITRACE_IHANDLER */

#ifdef CONFIG_ITRACE_IRQSOFF
extern void itrace_hardirqs_on(void);
extern void itrace_hardirqs_off(void);
extern void itrace_hardirqs_ignore(void);
extern void itrace_irqsoff_set(u64 set);
extern void itrace_irqsoff_get(struct Irqsoff *is, int cpu);
extern void itrace_irqsoff_num_set(int set);
extern int itrace_irqsoff_num_get(void);
#else
# define itrace_hardirqs_on() do { } while (0)
# define itrace_hardirqs_on() do { } while (0)
#endif /* CONFIG_ITRACE_IRQSOFF */

#endif /* __LINUX_ITRACE_H */
