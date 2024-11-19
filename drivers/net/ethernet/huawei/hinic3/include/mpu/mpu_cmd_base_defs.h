/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef MPU_CMD_BASE_DEFS_H
#define MPU_CMD_BASE_DEFS_H

#include "mgmt_msg_base.h"
#include "comm_defs.h"

enum hinic3_svc_type {
	SVC_T_COMM = 0,
	SVC_T_NIC,
	SVC_T_OVS,
	SVC_T_ROCE,
	SVC_T_TOE,
	SVC_T_IOE,
	SVC_T_FC,
	SVC_T_VBS,
	SVC_T_IPSEC,
	SVC_T_VIRTIO,
	SVC_T_MIGRATE,
	SVC_T_PPA,
	SVC_T_MAX,
};

#endif
