/*
 * Huawei Ascend Kexec Mailbox
 *
 * Copyright (C) 2020 Huawei Limited
 * Author: Huawei OS Kernel Lab
 *
 * This code is based on the hisilicon ascend platform.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/of.h>
#include <linux/of_address.h>

#include <asm/cacheflush.h>

#define MAGIC_NO	0x42494F53UL
#define MAILBOX_ADDR	0x880000000UL

struct kexec_mailbox {
	unsigned long magic;
	phys_addr_t reboot_code_phys;
	unsigned long kimage_head;
	unsigned long kimage_start;
	unsigned long kimage_pad;
};

/* Global variables for the arm64_relocate_new_kernel routine. */
extern const unsigned char arm64_relocate_new_kernel[];
extern const unsigned long arm64_relocate_new_kernel_size;

unsigned long mailbox_addr = MAILBOX_ADDR;

int bios_setup_kimage(struct kimage *kimage)
{
	struct kexec_mailbox *bios_addr;
	phys_addr_t reboot_code_buffer_phys;
	void *reboot_code_buffer;
	struct device_node *np;

	/* setup mailbox addr */
	np = of_find_node_by_name(NULL, "kexecmailbox");
	if (np) {
		struct resource res;

		of_address_to_resource(np, 0, &res);
		mailbox_addr = res.start;
		of_node_put(np);
		pr_info("kexec_mailbox: use dtb config addr %lx\n", mailbox_addr);
	} else
		pr_info("kexec_mailbox: use default addr %lx\n", mailbox_addr);

	bios_addr = ioremap_cache(mailbox_addr, sizeof(struct kexec_mailbox));
	if (!bios_addr)
		return -EINVAL;

	reboot_code_buffer_phys = page_to_phys(kimage->control_code_page);
	reboot_code_buffer = phys_to_virt(reboot_code_buffer_phys);
	memcpy(reboot_code_buffer, arm64_relocate_new_kernel,
			arm64_relocate_new_kernel_size);
	__flush_dcache_area(reboot_code_buffer, arm64_relocate_new_kernel_size);
	__flush_icache_range((uintptr_t)reboot_code_buffer,
			arm64_relocate_new_kernel_size);

	bios_addr->magic = MAGIC_NO;
	bios_addr->reboot_code_phys = reboot_code_buffer_phys;
	bios_addr->kimage_head = kimage->head;
	bios_addr->kimage_start = kimage->start;
	bios_addr->kimage_pad = 0;
	pr_info("kexec_mailbox: magic %lx, reboot_code_phys %llx kimage_head %lx kimage_start %lx kimage_pad %lx\n",
			bios_addr->magic,
			bios_addr->reboot_code_phys, bios_addr->kimage_head,
			bios_addr->kimage_start, bios_addr->kimage_pad);
	__flush_dcache_area(bios_addr, sizeof(struct kexec_mailbox));
	__flush_icache_range((uintptr_t)bios_addr, sizeof(struct kexec_mailbox));

	iounmap((void __iomem *)mailbox_addr);
	return 0;
}
