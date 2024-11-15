/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2024. Huawei Technologies Co., Ltd. All rights reserved.
 */
#ifndef __LINUX_IMA_VIRTCCA_H
#define __LINUX_IMA_VIRTCCA_H

#include "ima.h"

#ifdef CONFIG_HISI_VIRTCCA_GUEST
int __init ima_virtcca_init(void);
bool ima_virtcca_available(void);
int ima_virtcca_extend(struct tpm_digest *digests_arg);
int ima_calc_virtcca_boot_aggregate(struct ima_digest_data *hash);
#else
static inline int __init ima_virtcca_init(void)
{
	return -ENODEV;
}

static inline bool ima_virtcca_available(void)
{
	return false;
}

static inline int ima_virtcca_extend(struct tpm_digest *digests_arg)
{
	return -ENODEV;
}

static inline int ima_calc_virtcca_boot_aggregate(struct ima_digest_data *hash)
{
	return -ENODEV;
}
#endif
#endif
