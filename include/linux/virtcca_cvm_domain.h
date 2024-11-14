/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024. Huawei Technologies Co., Ltd. All rights reserved.
 */

#ifndef __VIRTCCA_CVM_DOMAIN_H
#define __VIRTCCA_CVM_DOMAIN_H

#ifdef CONFIG_HISI_VIRTCCA_GUEST

#include <asm/virtcca_cvm_guest.h>
static inline bool virtcca_cvm_domain(void)
{
	return is_virtcca_cvm_world();
}

extern void enable_swiotlb_for_cvm_dev(struct device *dev, bool enable);

#else
static inline bool virtcca_cvm_domain(void)
{
	return false;
}

static inline void enable_swiotlb_for_cvm_dev(struct device *dev, bool enable) {}

#endif

#endif /* __VIRTCCA_CVM_DOMAIN_H */
