.. SPDX-License-Identifier: GPL-2.0

=============
Interrupts Tracing
=============

:Author: Bixuan Cui

1. Introduction
===============

Itrace (Interrupt Tracing) is a lightweight interrupt tracing tool. It supports
the following functions:

* Ihandler(Interrupt Handler) tracer can trace and calculate the time consumed of
  the hardware irq function and list the name, number and duration of the interrupt.

* Irqsoff tracer can trace the areas that disable interrupts.

* Ihandler and Irqsoff support dynamic disable and threshold setting.

2. Using Ihandler Tracing
======================

2.1 Enable Ihandler Tracing
---------------------------------

Echo threshold val to /proc/irq/itrace_ihandler to enable ihandler tracer. The
threshold value ranges from 1 to 10000000, in microsecond. For example::

        # echo 20 > /proc/irq/itrace_ihandler

Cat /proc/irq/itrace_ihandler to get the message of ihandler. For example::

        # echo 1 > /proc/irq/itrace_ihandler
        # cat /proc/irq/itrace_ihandler
        [irq_handler CPU0]:
          irq:14 name:uart-pl011 max_time:8(us) count:278
          irq:31 name:ufshcd max_time:44(us) count:1684
          irq:565 name:mailbox-1-lp-rx-acp max_time:6(us) count:10
          irq:602 name:devdrv-functional_c max_time:1(us) count:1

Note: Only the captured information is displayed. Five lines for each cpu
      by default.

2.2 Disable Ihandler Tracing
---------------------------------

Echo 0 to /proc/irq/itrace_ihandler to disable ihandler tracer. For example::

        # echo 0 > /proc/irq/itrace_ihandler

2.3 Set the number of displayed
---------------------------------

Echo num to /proc/irq/itrace_ihandler_num to set the number of displayed. The
num value ranges from 1 to 30. For example::

        # echo 20 > /proc/irq/itrace_ihandler_num

3. Using Irqsoff Tracing
======================

3.1 Enable Irqsoff Tracing
---------------------------------

Echo threshold val to /proc/irq/itrace_irqsoff to enable irqsoff tracer. The
threshold value ranges from 1 to 10000000, in microsecond. For example::

        # echo 20 > /proc/irq/itrace_irqsoff

Cat /proc/irq/itrace_irqsoff to get the message of irqsoff. For example::

        # echo 1 > /proc/irq/itrace_irqsoff
        # cat /proc/irq/itrace_irqsoff
        [irqsoff CPU0]:
          max_time:3(us) caller:__do_softirq+0x94/0x328
          max_time:4(us) caller:__do_softirq+0x94/0x328
          max_time:4(us) caller:__do_softirq+0x94/0x328
        [irqsoff CPU1]:
          max_time:2(us) caller:finish_task_switch+0x6c/0x1e0
          max_time:1(us) caller:__arm64_sys_setpgid+0xd0/0x1d8
          max_time:2(us) caller:pagevec_lru_move_fn+0x18c/0x1c8
        [irqsoff CPU2]:
          max_time:4(us) caller:__do_softirq+0x94/0x328
          max_time:6(us) caller:__do_softirq+0x94/0x328
          max_time:2(us) caller:rcu_idle_exit+0xa4/0xd8
        [irqsoff CPU3]:
          max_time:3(us) caller:rcu_idle_exit+0xa4/0xd8
          max_time:1(us) caller:__do_softirq+0x94/0x328
          max_time:2(us) caller:osal_spin_unlock_irqrestore+0x5c/0x80 [drv_osal]

Note: Only the captured information is displayed. Three lines for each cpu
      by default.

3.2 Disable Irqsoff Tracing
---------------------------------

Echo 0 to /proc/irq/itrace_irqsoff to disable irqsoff tracer. For example::

        # echo 0 > /proc/irq/itrace_irqsoff

3.3 Set the number of displayed
---------------------------------

Echo num to /proc/irq/itrace_irqsoff_num to set the number of displayed.
The num value ranges from 1 to 30. For example::

        # echo 20 > /proc/irq/itrace_irqsoff_num
