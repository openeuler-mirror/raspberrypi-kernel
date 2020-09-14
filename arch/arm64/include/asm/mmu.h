/*
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __ASM_MMU_H
#define __ASM_MMU_H

#define MMCF_AARCH32	0x1	/* mm context flag for AArch32 executables */
#define USER_ASID_BIT	48
#define USER_ASID_FLAG	(UL(1) << USER_ASID_BIT)
#define TTBR_ASID_MASK	(UL(0xffff) << 48)

#define BP_HARDEN_EL2_SLOTS 4

#ifndef __ASSEMBLY__

typedef struct {
	atomic64_t	id;
	unsigned long	pinned;
	void		*vdso;
	unsigned long refcount;
	unsigned long	flags;
} mm_context_t;

#define MAX_RES_REGIONS	32

struct res_mem {
	phys_addr_t base;
	phys_addr_t size;
};

extern struct res_mem res_mem[MAX_RES_REGIONS];
extern int res_mem_count;

/*
 * This macro is only used by the TLBI code, which cannot race with an
 * ASID change and therefore doesn't need to reload the counter using
 * atomic64_read.
 */
#define ASID(mm)	((mm)->context.id.counter & 0xffff)

static inline bool arm64_kernel_unmapped_at_el0(void)
{
	return IS_ENABLED(CONFIG_UNMAP_KERNEL_AT_EL0) &&
	       cpus_have_const_cap(ARM64_UNMAP_KERNEL_AT_EL0);
}

/*
 * This check is triggered during the early boot before the cpufeature
 * is initialised. Checking the status on the local CPU allows the boot
 * CPU to detect the need for non-global mappings and thus avoiding a
 * pagetable re-write after all the CPUs are booted. This check will be
 * anyway run on individual CPUs, allowing us to get the consistent
 * state once the SMP CPUs are up and thus make the switch to non-global
 * mappings if required.
 */
static inline bool kaslr_requires_kpti(void)
{
	u64 ftr;

	if (!IS_ENABLED(CONFIG_RANDOMIZE_BASE))
		return false;

	/*
	 * E0PD does a similar job to KPTI so can be used instead
	 * where available.
	 */
	if (IS_ENABLED(CONFIG_ARM64_E0PD)) {
		ftr = read_sysreg_s(SYS_ID_AA64MMFR2_EL1);
		if ((ftr >> ID_AA64MMFR2_E0PD_SHIFT) & 0xf)
			return false;
	}

	return kaslr_offset() > 0;
}

static inline bool arm64_kernel_use_ng_mappings(void)
{
	/* What's a kpti? Use global mappings if we don't know. */
	if (!IS_ENABLED(CONFIG_UNMAP_KERNEL_AT_EL0))
		return false;

	/*
	 * Note: this function is called before the CPU capabilities have
	 * been configured, so our early mappings will be global. If we
	 * later determine that kpti is required, then
	 * kpti_install_ng_mappings() will make them non-global.
	 */
	if (arm64_kernel_unmapped_at_el0())
		return true;

	/*
	 * Once we are far enough into boot for capabilities to be
	 * ready we will have confirmed if we are using non-global
	 * mappings so don't need to consider anything else here.
	 */
	if (static_branch_likely(&arm64_const_caps_ready))
		return false;

	/*
	 * KASLR is enabled so we're going to be enabling kpti on non-broken
	 * CPUs regardless of their susceptibility to Meltdown. Rather
	 * than force everybody to go through the G -> nG dance later on,
	 * just put down non-global mappings from the beginning
	 */
	return kaslr_requires_kpti();
}

typedef void (*bp_hardening_cb_t)(void);

struct bp_hardening_data {
	int			hyp_vectors_slot;
	bp_hardening_cb_t	fn;
};

#if (defined(CONFIG_HARDEN_BRANCH_PREDICTOR) ||	\
     defined(CONFIG_HARDEN_EL2_VECTORS))
extern char __bp_harden_hyp_vecs_start[], __bp_harden_hyp_vecs_end[];
extern atomic_t arm64_el2_vector_last_slot;
#endif  /* CONFIG_HARDEN_BRANCH_PREDICTOR || CONFIG_HARDEN_EL2_VECTORS */

#ifdef CONFIG_HARDEN_BRANCH_PREDICTOR
DECLARE_PER_CPU_READ_MOSTLY(struct bp_hardening_data, bp_hardening_data);

static inline struct bp_hardening_data *arm64_get_bp_hardening_data(void)
{
	return this_cpu_ptr(&bp_hardening_data);
}

static inline void arm64_apply_bp_hardening(void)
{
	struct bp_hardening_data *d;

	if (!cpus_have_const_cap(ARM64_HARDEN_BRANCH_PREDICTOR))
		return;

	d = arm64_get_bp_hardening_data();
	if (d->fn)
		d->fn();
}
#else
static inline struct bp_hardening_data *arm64_get_bp_hardening_data(void)
{
	return NULL;
}

static inline void arm64_apply_bp_hardening(void)	{ }
#endif	/* CONFIG_HARDEN_BRANCH_PREDICTOR */

extern void paging_init(void);
extern void bootmem_init(void);
extern void __iomem *early_io_map(phys_addr_t phys, unsigned long virt);
extern void init_mem_pgprot(void);
extern void create_pgd_mapping(struct mm_struct *mm, phys_addr_t phys,
			       unsigned long virt, phys_addr_t size,
			       pgprot_t prot, bool page_mappings_only);
extern void *fixmap_remap_fdt(phys_addr_t dt_phys);
extern void mark_linear_text_alias_ro(void);

#endif	/* !__ASSEMBLY__ */
#endif
