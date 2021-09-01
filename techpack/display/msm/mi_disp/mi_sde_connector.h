/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 * Copyright (C) 2020 XiaoMi, Inc.
 */

#ifndef _MI_SDE_CONNECTOR_H_
#define _MI_SDE_CONNECTOR_H_

#include "mi_disp_config.h"
#include "drm_connector.h"

enum mi_layer_type {
	MI_DIMLAYER_NULL = 0x0,
	MI_DIMLAYER_FOD_HBM_OVERLAY = 0x1,
	MI_DIMLAYER_FOD_ICON = 0x2,
	MI_DIMLAYER_AOD = 0x4,
	MI_FOD_UNLOCK_SUCCESS = 0x8,
	MI_DIMLAYER_MAX,
};

enum mi_hbm_op_code {
	MI_FOD_HBM_ON = 0,
	MI_FOD_HBM_OFF,
};

struct mi_layer_state
{
	enum mi_layer_type mi_layer_type;
	uint32_t current_backlight;
};

#if MI_DISP_DEBUGFS_ENABLE
int mi_sde_connector_debugfs_esd_sw_trigger(void *display);
#else
static inline int mi_sde_connector_debugfs_esd_sw_trigger(void *display) { return 0; }
#endif

int mi_sde_connector_hbm_ctl(struct drm_connector *connector, uint32_t op_code);

void mi_sde_connector_update_layer_state(struct drm_connector *connector,
	enum mi_layer_type mi_layer_type);

int mi_sde_connector_fod_hbm_fence(struct drm_connector *connector);

void mi_sde_connector_fod_notify(struct drm_connector *conn);

#endif /* _MI_SDE_CONNECTOR_H_ */
