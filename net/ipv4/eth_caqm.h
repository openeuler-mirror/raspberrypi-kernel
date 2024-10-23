/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024
 * All rights reserved.
 *
 * CAQM for the eth neigh output, we need to skip the hh_cache
 * Authors:	Chengjun Jia <jiachengjun2@huawei.com>
 */
#ifndef _LINUX_ETH_CAQM_H_
#define _LINUX_ETH_CAQM_H_

#include <linux/if_caqm.h>

#ifdef CONFIG_ETH_CAQM
static inline int caqm_neigh_output(struct neighbour *neigh, struct sk_buff *skb,
				   bool skip_cache, struct net_device *dev)
{
	int res;

	const struct hh_cache *hh = &neigh->hh;
	struct skb_caqm_info *cinfo = get_skb_caqm_info(skb);
	// If the nic is not configed, the output packet has no caqm header
	if (!skip_cache &&
	    (!static_branch_unlikely(&sysctl_caqm_enable) || !(cinfo->send_en)) &&
	    (READ_ONCE(neigh->nud_state) & NUD_CONNECTED) &&
	    READ_ONCE(hh->hh_len))
		res = neigh_hh_output(hh, skb);
	else {
		if ((sysctl_caqm_filter_nics & (1UL << dev->ifindex)) == 0)
			cinfo->send_en = 0;
		res = neigh->output(neigh, skb);
	}
	return res;
}
#endif

#endif
