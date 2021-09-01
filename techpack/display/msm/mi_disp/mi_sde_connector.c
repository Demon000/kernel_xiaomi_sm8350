// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 * Copyright (C) 2020 XiaoMi, Inc.
 */

#define pr_fmt(fmt) "mi_sde_connector:[%s:%d] " fmt, __func__, __LINE__

#include <drm/sde_drm.h>
#include "msm_drv.h"
#include "sde_connector.h"
#include "sde_encoder.h"
#include "sde_trace.h"
#include "dsi_display.h"
#include "dsi_panel.h"

#include "mi_disp_print.h"
#include "mi_disp_feature.h"
#include "mi_dsi_panel.h"
#include "mi_dsi_display.h"

enum local_hbm_target_brightness {
	LOCAL_HBM_TARGET_BRIGHTNESS_NONE,
	LOCAL_HBM_TARGET_BRIGHTNESS_WHITE_1000NIT,
	LOCAL_HBM_TARGET_BRIGHTNESS_WHITE_110NIT,
	LOCAL_HBM_TARGET_BRIGHTNESS_GREEN_500NIT,
	LOCAL_HBM_TARGET_BRIGHTNESS_MAX
};

void mi_sde_connector_fod_ui_ready(struct dsi_display *display, int type, int value);

static int mi_sde_get_fod_hbm_target_brightness(struct dsi_display *display)
{
	int brightness_clone = 0;
	int target = LOCAL_HBM_TARGET_BRIGHTNESS_WHITE_1000NIT;

	if (display->panel->mi_cfg.feature_val[DISP_FEATURE_LOW_BRIGHTNESS_FOD]) {
		if (is_aod_and_panel_initialized(display->panel) ||
				display->panel->power_mode == SDE_MODE_DPMS_OFF) {
			if (display->panel->mi_cfg.feature_val[DISP_FEATURE_SENSOR_LUX] <
					display->panel->mi_cfg.fod_low_brightness_lux_threshold)
				target = LOCAL_HBM_TARGET_BRIGHTNESS_WHITE_110NIT;
		} else {
			mi_dsi_panel_get_brightness_clone(display->panel, &brightness_clone);
			if (brightness_clone < display->panel->mi_cfg.fod_low_brightness_clone_threshold
				&& (display->panel->mi_cfg.feature_val[DISP_FEATURE_SENSOR_LUX] <
					display->panel->mi_cfg.fod_low_brightness_lux_threshold + 10)) {
				target = LOCAL_HBM_TARGET_BRIGHTNESS_WHITE_110NIT;
			}
		}
	}

	return target;
}

int mi_sde_connector_debugfs_esd_sw_trigger(void *display)
{
	struct dsi_display *dsi_display = (struct dsi_display *)display;
	struct drm_connector *connector = NULL;
	struct sde_connector *c_conn = NULL;
	struct drm_event event;
	int power_mode;

	const char *sde_power_mode_str[] = {
		[SDE_MODE_DPMS_ON] = "SDE_MODE_DPMS_ON",
		[SDE_MODE_DPMS_LP1] = "SDE_MODE_DPMS_LP1",
		[SDE_MODE_DPMS_LP2] = "SDE_MODE_DPMS_LP2",
		[SDE_MODE_DPMS_STANDBY] = "SDE_MODE_DPMS_STANDBY",
		[SDE_MODE_DPMS_SUSPEND] = "SDE_MODE_DPMS_SUSPEND",
		[SDE_MODE_DPMS_OFF] = "SDE_MODE_DPMS_OFF",
	};

	if (!dsi_display || !dsi_display->panel || !dsi_display->drm_conn) {
		DISP_ERROR("invalid display/panel/drm_conn ptr\n");
		return -EINVAL;
	}

	connector = dsi_display->drm_conn;
	c_conn = to_sde_connector(connector);
	if (!c_conn) {
		DISP_ERROR("invalid sde_connector ptr\n");
		return -EINVAL;
	}

	if (!dsi_panel_initialized(dsi_display->panel)) {
		DISP_ERROR("Panel not initialized\n");
		return -EINVAL;
	}

	if (atomic_read(&(dsi_display->panel->esd_recovery_pending))) {
		DISP_INFO("[esd-test]ESD recovery already pending\n");
		return 0;
	}

	if (c_conn->panel_dead) {
		DISP_INFO("panel_dead is true, return!\n");
		return 0;
	}

	atomic_set(&dsi_display->panel->esd_recovery_pending, 1);
	c_conn->panel_dead = true;
	DISP_ERROR("[esd-test]esd irq check failed report PANEL_DEAD conn_id: %d enc_id: %d\n",
			c_conn->base.base.id, c_conn->encoder->base.id);

	power_mode = dsi_display->panel->power_mode;
	DISP_INFO("[esd-test]power_mode = %s\n", sde_power_mode_str[power_mode]);
	if (power_mode == SDE_MODE_DPMS_ON || power_mode == SDE_MODE_DPMS_LP1) {
		sde_encoder_display_failure_notification(c_conn->encoder, false);
	}

	event.type = DRM_EVENT_PANEL_DEAD;
	event.length = sizeof(bool);
	msm_mode_object_event_notify(&c_conn->base.base,
			c_conn->base.dev, &event, (u8 *)&c_conn->panel_dead);

	return 0;
}

int mi_sde_connector_hbm_ctl(struct drm_connector *connector, uint32_t op_code)
{
	int ret = 0;
	struct sde_connector *c_conn = to_sde_connector(connector);
	struct disp_feature_ctl ctl;
	struct dsi_display *dsi_display;
	struct mi_dsi_panel_cfg *mi_cfg;

	dsi_display = (struct dsi_display *) c_conn->display;
	if (!dsi_display || !dsi_display->panel) {
		DISP_ERROR("invalid display/panel ptr\n");
		return -EINVAL;
	}

	if (mi_get_disp_id(dsi_display) != MI_DISP_PRIMARY)
		return -EINVAL;

	mi_cfg = &dsi_display->panel->mi_cfg;

	switch (op_code) {
	case MI_FOD_HBM_ON:
		if (mi_cfg->local_hbm_enabled) {
			ctl.feature_id = DISP_FEATURE_LOCAL_HBM;
			if (mi_cfg->feature_val[DISP_FEATURE_FP_STATUS] == HEART_RATE_START) {
				ctl.feature_val = LOCAL_HBM_NORMAL_GREEN_500NIT;
				mi_cfg->local_hbm_target = LOCAL_HBM_TARGET_BRIGHTNESS_GREEN_500NIT;
				break;
			}

			mi_cfg->local_hbm_target = mi_sde_get_fod_hbm_target_brightness(dsi_display);
			if (mi_cfg->feature_val[DISP_FEATURE_FP_STATUS] == ENROLL_START)
				mi_cfg->local_hbm_target = LOCAL_HBM_TARGET_BRIGHTNESS_WHITE_1000NIT;

			if (mi_cfg->local_hbm_target == LOCAL_HBM_TARGET_BRIGHTNESS_WHITE_1000NIT) {
				if (is_aod_and_panel_initialized(dsi_display->panel))
					ctl.feature_val = LOCAL_HBM_HLPM_WHITE_1000NIT;
				else
					ctl.feature_val = LOCAL_HBM_NORMAL_WHITE_1000NIT;
			} else if (mi_cfg->local_hbm_target == LOCAL_HBM_TARGET_BRIGHTNESS_WHITE_110NIT) {
				if (is_aod_and_panel_initialized(dsi_display->panel))
					ctl.feature_val = LOCAL_HBM_HLPM_WHITE_110NIT;
				else
					ctl.feature_val = LOCAL_HBM_NORMAL_WHITE_110NIT;
			}
		} else {
			ctl.feature_id = DISP_FEATURE_HBM_FOD;
			ctl.feature_val = FEATURE_ON;
		}
		break;
	case MI_FOD_HBM_OFF:
		if (mi_cfg->local_hbm_enabled) {
			ctl.feature_id = DISP_FEATURE_LOCAL_HBM;
			if (is_aod_and_panel_initialized(dsi_display->panel)) {
				if (mi_cfg->feature_val[DISP_FEATURE_FP_STATUS] == AUTH_STOP) {
					ctl.feature_val = LOCAL_HBM_OFF_TO_NORMAL;
					mi_cfg->doze_brightness = DOZE_TO_NORMAL;
					mi_cfg->doze_brightness_backup = DOZE_TO_NORMAL;
				} else if (dsi_display->panel->mi_cfg.doze_brightness == DOZE_BRIGHTNESS_HBM)
					ctl.feature_val = LOCAL_HBM_OFF_TO_HLPM;
				else
					ctl.feature_val = LOCAL_HBM_OFF_TO_LLPM;
			} else
				ctl.feature_val = LOCAL_HBM_OFF_TO_NORMAL;
			mi_cfg->local_hbm_target = LOCAL_HBM_TARGET_BRIGHTNESS_NONE;
		} else {
			ctl.feature_id = DISP_FEATURE_HBM_FOD;
			ctl.feature_val = FEATURE_OFF;
		}
		break;
	default:
		break;
	}
	SDE_ATRACE_BEGIN("mi_sde_connector_hbm_ctl");
	ret = mi_dsi_display_set_disp_param(c_conn->display, &ctl);
	SDE_ATRACE_END("mi_sde_connector_hbm_ctl");
	if (op_code == MI_FOD_HBM_OFF && mi_cfg->local_hbm_enabled)
		mi_sde_connector_fod_ui_ready(dsi_display, 2, 0);
	return ret;
}

void mi_sde_connector_update_layer_state(struct drm_connector *connector,
	enum mi_layer_type mi_layer_type)
{
	struct sde_connector *c_conn = to_sde_connector(connector);
	c_conn->mi_layer_state.mi_layer_type = mi_layer_type;
}

int mi_sde_connector_fod_hbm_fence(struct drm_connector *connector)
{
	int rc = 0;
	struct sde_connector *c_conn;
	struct dsi_display *dsi_display;
	bool target_overlay;
	struct mi_dsi_panel_cfg *mi_cfg;

	if (!connector) {
		DISP_ERROR("invalid connector ptr\n");
		return -EINVAL;
	}

	c_conn = to_sde_connector(connector);

	if (c_conn->connector_type != DRM_MODE_CONNECTOR_DSI)
		return 0;

	dsi_display = (struct dsi_display *) c_conn->display;
	if (!dsi_display || !dsi_display->panel) {
		DISP_ERROR("invalid display/panel ptr\n");
		return -EINVAL;
	}

	if (mi_get_disp_id(dsi_display) != MI_DISP_PRIMARY)
		return -EINVAL;

	mi_cfg = &dsi_display->panel->mi_cfg;

    if (mi_cfg->local_hbm_enabled) {
		target_overlay = c_conn->mi_layer_state.mi_layer_type & MI_DIMLAYER_FOD_ICON;
	} else {
		target_overlay = c_conn->mi_layer_state.mi_layer_type & MI_DIMLAYER_FOD_HBM_OVERLAY;
	}

	if (target_overlay) {
		if (mi_cfg->fod_hbm_layer_enabled == false && c_conn->allow_bl_update) {
			if (mi_cfg->delay_before_fod_hbm_on)
				sde_encoder_wait_for_event(c_conn->encoder, MSM_ENC_VBLANK);

			mi_sde_connector_hbm_ctl(connector, MI_FOD_HBM_ON);

			mi_cfg->fod_hbm_layer_enabled = true;
		}
	} else {
		if (mi_cfg->fod_hbm_layer_enabled == true) {

			if (mi_cfg->delay_before_fod_hbm_off)
				sde_encoder_wait_for_event(c_conn->encoder, MSM_ENC_VBLANK);

			mi_sde_connector_hbm_ctl(connector, MI_FOD_HBM_OFF);

			mi_cfg->fod_hbm_layer_enabled = false;
		}
	}

	return rc;
}


void mi_sde_connector_fod_ui_ready(struct dsi_display *display, int type, int value)
{
	struct disp_event d_event;

	if (!display) {
		DISP_ERROR("invalid display ptr\n");
		return;
	}

	if (mi_get_disp_id(display) != MI_DISP_PRIMARY)
		return;

	if (type == 1) /* HBM */
	{
		if (value == 0)
			display->panel->mi_cfg.fod_ui_ready &= ~0x01;
		else if (value == 1)
			display->panel->mi_cfg.fod_ui_ready |= 0x01;
	}

	if (type == 2) /* ICON */
	{
		if (value == 0) {
			if (display->panel->mi_cfg.local_hbm_enabled)
				display->panel->mi_cfg.fod_ui_ready &= ~0x07;
			else
				display->panel->mi_cfg.fod_ui_ready &= ~0x02;
		} else if (value == 1) {
			if (display->panel->mi_cfg.local_hbm_enabled) {
				if (display->panel->mi_cfg.local_hbm_target == LOCAL_HBM_TARGET_BRIGHTNESS_WHITE_1000NIT
					|| display->panel->mi_cfg.local_hbm_target == LOCAL_HBM_TARGET_BRIGHTNESS_GREEN_500NIT)
					/*Local HBM only monitor ICON layer*/
					display->panel->mi_cfg.fod_ui_ready |= 0x03;
				else if (display->panel->mi_cfg.local_hbm_target == LOCAL_HBM_TARGET_BRIGHTNESS_WHITE_110NIT)
					display->panel->mi_cfg.fod_ui_ready |= 0x07;
			} else
				display->panel->mi_cfg.fod_ui_ready |= 0x02;
		}
	}

	DISP_INFO("fod_ui_ready notify=%d\n", display->panel->mi_cfg.fod_ui_ready);

	d_event.disp_id = mi_get_disp_id(display);
	d_event.type = MI_DISP_EVENT_FOD;
	d_event.length = sizeof(display->panel->mi_cfg.fod_ui_ready);
	mi_disp_feature_event_notify(&d_event, (u8 *)&display->panel->mi_cfg.fod_ui_ready);
}

void mi_sde_connector_fod_notify(struct drm_connector *conn)
{
	struct sde_connector *c_conn;
	bool icon, hbm_state;
	static bool last_icon = false;
	static bool last_hbm_state = false;
	struct dsi_display *dsi_display;

	if (!conn) {
		DISP_ERROR("invalid params\n");
		return;
	}

	c_conn = to_sde_connector(conn);
	if (c_conn->connector_type != DRM_MODE_CONNECTOR_DSI) {
		DISP_ERROR("not DRM_MODE_CONNECTOR_DSIl\n");
		return;
	}

	dsi_display = (struct dsi_display *) c_conn->display;
	if (!dsi_display || !dsi_display->panel) {
		DISP_ERROR("invalid display/panel ptr\n");
		return;
	}

	if (mi_get_disp_id(dsi_display) != MI_DISP_PRIMARY)
		return;

	icon = c_conn->mi_layer_state.mi_layer_type & MI_DIMLAYER_FOD_ICON;
	if (last_icon != icon) {
		if (icon) {
			/* With local hbm, it will enable after first frame tx complete.
			 * So skip fod notify before local fod hbm enabled.
			 */
			if (dsi_display->panel->mi_cfg.local_hbm_enabled
				&& !dsi_display->panel->mi_cfg.fod_hbm_layer_enabled) {
				return;
			}
			/* Make sure icon was displayed on panel before notifying
			 * fingerprint to capture image */
			if (dsi_display->panel->mi_cfg.fod_hbm_layer_enabled) {
				sde_encoder_wait_for_event(c_conn->encoder,
						MSM_ENC_TX_COMPLETE);
				sde_encoder_wait_for_event(c_conn->encoder,
						MSM_ENC_VBLANK);
			}
			SDE_ATRACE_BEGIN("mi_sde_connector_fod_ui_ready");
			mi_sde_connector_fod_ui_ready(dsi_display, 2, 1);
			SDE_ATRACE_END("mi_sde_connector_fod_ui_ready");
		} else {
			if (!dsi_display->panel->mi_cfg.local_hbm_enabled)
				mi_sde_connector_fod_ui_ready(dsi_display, 2, 0);
		}
	}
	last_icon = icon;

	/*We don't moniter hbm layer on local hbm project*/
	if (!dsi_display->panel->mi_cfg.local_hbm_enabled) {
		hbm_state = dsi_display->panel->mi_cfg.fod_hbm_layer_enabled;
		if (last_hbm_state != hbm_state) {
			if (hbm_state) {
			   /* The black screen fingerprint unlocks, waits for HBM effect */
				if (icon) {
					sde_encoder_wait_for_event(c_conn->encoder,
							MSM_ENC_TX_COMPLETE);
				}
				mi_sde_connector_fod_ui_ready(dsi_display, 1, 1);
			} else {
				mi_sde_connector_fod_ui_ready(dsi_display, 1, 0);
			}
		}
		last_hbm_state = hbm_state;
	}
}

