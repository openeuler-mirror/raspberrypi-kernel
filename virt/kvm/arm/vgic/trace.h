/* SPDX-License-Identifier: GPL-2.0 */
#if !defined(_TRACE_VGIC_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_VGIC_H

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm

TRACE_EVENT(vgic_update_irq_pending,
	TP_PROTO(unsigned long vcpu_id, __u32 irq, bool level),
	TP_ARGS(vcpu_id, irq, level),

	TP_STRUCT__entry(
		__field(	unsigned long,	vcpu_id	)
		__field(	__u32,		irq	)
		__field(	bool,		level	)
	),

	TP_fast_assign(
		__entry->vcpu_id	= vcpu_id;
		__entry->irq		= irq;
		__entry->level		= level;
	),

	TP_printk("VCPU: %ld, IRQ %d, level: %d",
		  __entry->vcpu_id, __entry->irq, __entry->level)
);

TRACE_EVENT(compute_ap_list_depth,
	TP_PROTO(unsigned long vcpu_id, __u32 irq, __u32 hwirq,  __u8 source,
		 __u8 priority, bool level, bool pending_latch, bool active,
		 bool enabled, bool hw, bool config),
	TP_ARGS(vcpu_id, irq, hwirq, source, priority, level, pending_latch,
		active, enabled, hw, config),

	TP_STRUCT__entry(
		__field(unsigned long,	vcpu_id)
		__field(__u32,		irq)
		__field(__u32,		hwirq)
		__field(__u8,		source)
		__field(__u8,		priority)
		__field(bool,		level)
		__field(bool,		pending_latch)
		__field(bool,		active)
		__field(bool,		enabled)
		__field(bool,		hw)
		__field(bool,		config)
	),

	TP_fast_assign(
		__entry->vcpu_id	= vcpu_id;
		__entry->irq		= irq;
		__entry->hwirq		= hwirq;
		__entry->source		= source;
		__entry->priority	= priority;
		__entry->level		= level;
		__entry->pending_latch	= pending_latch;
		__entry->active		= active;
		__entry->enabled	= enabled;
		__entry->hw			= hw;
		__entry->config		= config;
	),

	TP_printk("VCPU: %ld, IRQ %d, HWIRQ: %d, SOURCE: %d, PRIORITY: %d, level: %d, pending_latch: %d, active: %d, enabled: %d, hw: %d, config: %d",
		  __entry->vcpu_id, __entry->irq, __entry->hwirq,
		  __entry->source, __entry->priority, __entry->level,
		  __entry->pending_latch,  __entry->active,
		  __entry->enabled, __entry->hw, __entry->config)
);

TRACE_EVENT(vgic_set_underflow,
	TP_PROTO(unsigned long vcpu_id),
	TP_ARGS(vcpu_id),

	TP_STRUCT__entry(
		__field(unsigned long,	vcpu_id)
	),

	TP_fast_assign(
		__entry->vcpu_id	= vcpu_id;
	),

	TP_printk("VCPU: %ld", __entry->vcpu_id)
);

TRACE_EVENT(vgic_flush_lr_state,
	TP_PROTO(unsigned long vcpu_id, unsigned int used_lrs, bool multi_sgi),
	TP_ARGS(vcpu_id, used_lrs, multi_sgi),

	TP_STRUCT__entry(
		__field(unsigned long,	vcpu_id)
		__field(unsigned int,	used_lrs)
		__field(bool,			multi_sgi)
	),

	TP_fast_assign(
		__entry->vcpu_id	= vcpu_id;
		__entry->used_lrs	= used_lrs;
		__entry->multi_sgi	= multi_sgi;
	),

	TP_printk("VCPU: %ld, used_lrs: %d, multi_sgi: %d",
		  __entry->vcpu_id, __entry->used_lrs, __entry->multi_sgi)
);

TRACE_EVENT(vgic_v3_populate_lr,
	TP_PROTO(unsigned long vcpu_id, __u32 irq, __u64 val, int lr),
	TP_ARGS(vcpu_id, irq, val, lr),

	TP_STRUCT__entry(
		__field(unsigned long,	vcpu_id)
		__field(__u32,		irq)
		__field(__u64,		val)
		__field(int,		lr)
	),

	TP_fast_assign(
		__entry->vcpu_id	= vcpu_id;
		__entry->irq		= irq;
		__entry->val		= val;
		__entry->lr		= lr;
	),

	TP_printk("VCPU: %ld, IRQ: %d, LR: 0x%llx, Index: %d",
		  __entry->vcpu_id, __entry->irq, __entry->val, __entry->lr)
);

TRACE_EVENT(vgic_v3_fold_lr_state,
	TP_PROTO(unsigned long vcpu_id, __u32 irq, __u64 val, int lr),
	TP_ARGS(vcpu_id, irq, val, lr),

	TP_STRUCT__entry(
		__field(unsigned long,	vcpu_id)
		__field(__u32,		irq)
		__field(__u64,		val)
		__field(int,		lr)
	),

	TP_fast_assign(
		__entry->vcpu_id	= vcpu_id;
		__entry->irq		= irq;
		__entry->val		= val;
		__entry->lr		= lr;
	),

	TP_printk("VCPU: %ld, IRQ: %d, LR: 0x%llx, Index: %d",
		  __entry->vcpu_id, __entry->irq, __entry->val, __entry->lr)
);

TRACE_EVENT(vgic_v3_populate_lr_vgic_if,
	TP_PROTO(unsigned long vcpu_id, unsigned long hcr, unsigned long vmcr,
		 unsigned long sre, unsigned long ap0r0,
		 unsigned long ap0r1, unsigned long ap0r2, unsigned long ap0r3,
		 unsigned long ap1r0, unsigned long ap1r1, unsigned long ap1r2,
		 unsigned long ap1r3),
	TP_ARGS(vcpu_id, hcr, vmcr, sre, ap0r0, ap0r1, ap0r2, ap0r3,
		ap1r0, ap1r1, ap1r2, ap1r3),

	TP_STRUCT__entry(
		__field(unsigned long,	vcpu_id)
		__field(unsigned long,	hcr)
		__field(unsigned long,	vmcr)
		__field(unsigned long,	sre)
		__field(unsigned long,	ap0r0)
		__field(unsigned long,	ap0r1)
		__field(unsigned long,	ap0r2)
		__field(unsigned long,	ap0r3)
		__field(unsigned long,	ap1r0)
		__field(unsigned long,	ap1r1)
		__field(unsigned long,	ap1r2)
		__field(unsigned long,	ap1r3)
	),

	TP_fast_assign(
		__entry->vcpu_id	= vcpu_id;
		__entry->hcr		= hcr;
		__entry->vmcr		= vmcr;
		__entry->sre		= sre;
		__entry->ap0r0		= ap0r0;
		__entry->ap0r1		= ap0r1;
		__entry->ap0r2		= ap0r2;
		__entry->ap0r3		= ap0r3;
		__entry->ap1r0		= ap1r0;
		__entry->ap1r1		= ap1r1;
		__entry->ap1r2		= ap1r2;
		__entry->ap1r3		= ap1r3;
	),

	TP_printk("VCPU: %ld, HCR: 0x%lx, VMCR: 0x%lx, SRE: 0x%lx, ap0r0: 0x%lx, ap0r1: 0x%lx, ap0r2: 0x%lx, ap0r3: 0x%lx, ap1r0: 0x%lx, ap1r1: 0x%lx, ap1r2: 0x%lx, ap1r3: 0x%lx,",
		  __entry->vcpu_id, __entry->hcr, __entry->vmcr,
		  __entry->sre, __entry->ap0r0, __entry->ap0r1,
		  __entry->ap0r2, __entry->ap0r3, __entry->ap1r0,
		  __entry->ap1r1, __entry->ap1r2, __entry->ap1r3)
);

TRACE_EVENT(vgic_v3_fold_lr_state_vgic_if,
	TP_PROTO(unsigned long vcpu_id, unsigned long hcr, unsigned long vmcr,
		 unsigned long sre, unsigned long ap0r0,
		 unsigned long ap0r1, unsigned long ap0r2, unsigned long ap0r3,
		 unsigned long ap1r0, unsigned long ap1r1, unsigned long ap1r2,
		 unsigned long ap1r3),
	TP_ARGS(vcpu_id, hcr, vmcr, sre, ap0r0, ap0r1, ap0r2, ap0r3,
		ap1r0, ap1r1, ap1r2, ap1r3),

	TP_STRUCT__entry(
		__field(unsigned long,	vcpu_id)
		__field(unsigned long,	hcr)
		__field(unsigned long,	vmcr)
		__field(unsigned long,	sre)
		__field(unsigned long,	ap0r0)
		__field(unsigned long,	ap0r1)
		__field(unsigned long,	ap0r2)
		__field(unsigned long,	ap0r3)
		__field(unsigned long,	ap1r0)
		__field(unsigned long,	ap1r1)
		__field(unsigned long,	ap1r2)
		__field(unsigned long,	ap1r3)
	),

	TP_fast_assign(
		__entry->vcpu_id	= vcpu_id;
		__entry->hcr		= hcr;
		__entry->vmcr		= vmcr;
		__entry->sre		= sre;
		__entry->ap0r0		= ap0r0;
		__entry->ap0r1		= ap0r1;
		__entry->ap0r2		= ap0r2;
		__entry->ap0r3		= ap0r3;
		__entry->ap1r0		= ap1r0;
		__entry->ap1r1		= ap1r1;
		__entry->ap1r2		= ap1r2;
		__entry->ap1r3		= ap1r3;
	),

	TP_printk("VCPU: %ld, HCR: 0x%lx, VMCR: 0x%lx, SRE: 0x%lx, ap0r0: 0x%lx, ap0r1: 0x%lx, ap0r2: 0x%lx, ap0r3: 0x%lx, ap1r0: 0x%lx, ap1r1: 0x%lx, ap1r2: 0x%lx, ap1r3: 0x%lx,",
		  __entry->vcpu_id, __entry->hcr, __entry->vmcr,
		  __entry->sre, __entry->ap0r0, __entry->ap0r1,
		  __entry->ap0r2,  __entry->ap0r3, __entry->ap1r0,
		  __entry->ap1r1, __entry->ap1r2,  __entry->ap1r3)
);


#endif /* _TRACE_VGIC_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../../virt/kvm/arm/vgic
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

/* This part must be outside protection */
#include <trace/define_trace.h>
