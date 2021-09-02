/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 * Copyright (C) 2020 XiaoMi, Inc.
 */

#define pr_fmt(fmt)	"mi-disp-parse:[%s:%d] " fmt, __func__, __LINE__
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>

#include "dsi_panel.h"
#include "dsi_parser.h"

#include "mi_disp_print.h"

#define DEFAULT_HBM_BL_MIN_LEVEL 1
#define DEFAULT_HBM_BL_MAX_LEVEL 2047
#define DEFAULT_MAX_BRIGHTNESS_CLONE 4095

int mi_dsi_panel_parse_esd_gpio_config(struct dsi_panel *panel)
{
	int rc = 0;
	struct dsi_parser_utils *utils = &panel->utils;
	struct mi_dsi_panel_cfg *mi_cfg = &panel->mi_cfg;

	mi_cfg->esd_err_irq_gpio = of_get_named_gpio_flags(
			utils->data, "mi,esd-err-irq-gpio",
			0, (enum of_gpio_flags *)&(mi_cfg->esd_err_irq_flags));
	if (gpio_is_valid(mi_cfg->esd_err_irq_gpio)) {
		mi_cfg->esd_err_irq = gpio_to_irq(mi_cfg->esd_err_irq_gpio);
		rc = gpio_request(mi_cfg->esd_err_irq_gpio, "esd_err_irq_gpio");
		if (rc)
			DISP_ERROR("Failed to request esd irq gpio %d, rc=%d\n",
				mi_cfg->esd_err_irq_gpio, rc);
		else
			gpio_direction_input(mi_cfg->esd_err_irq_gpio);
	} else {
		rc = -EINVAL;
	}

	return rc;
}

static int mi_dsi_panel_parse_gamma_config(struct dsi_panel *panel)
{
	int rc = 0;
	struct dsi_parser_utils *utils = &panel->utils;
	struct mi_dsi_panel_cfg *mi_cfg = &panel->mi_cfg;

	if (mi_cfg->gamma_update_flag) {
		rc = utils->read_u32(utils->data,
				"mi,mdss-dsi-panel-gamma-flash-read-total-param",
				&mi_cfg->gamma_cfg.flash_read_total_param);
		if (rc)
			DISP_INFO("failed to get mi,mdss-dsi-panel-gamma-flash-read-total-param\n");

		rc = utils->read_u32(utils->data,
				"mi,mdss-dsi-panel-gamma-update-b8-index",
				&mi_cfg->gamma_cfg.update_b8_index);
		if (rc)
			DISP_INFO("failed to get mi,mdss-dsi-panel-gamma-update-b8-index\n");

		rc = utils->read_u32(utils->data,
				"mi,mdss-dsi-panel-gamma-update-b9-index",
				&mi_cfg->gamma_cfg.update_b9_index);
		if (rc)
			DISP_INFO("failed to get mi,mdss-dsi-panel-gamma-update-b9-index\n");

		rc = utils->read_u32(utils->data,
				"mi,mdss-dsi-panel-gamma-update-ba-index",
				&mi_cfg->gamma_cfg.update_ba_index);
		if (rc)
			DISP_INFO("failed to get mi,mdss-dsi-panel-gamma-update-ba-index\n");
	}

	return rc;
}


int mi_dsi_panel_parse_config(struct dsi_panel *panel)
{
	int rc = 0;
	struct dsi_parser_utils *utils = &panel->utils;
	struct mi_dsi_panel_cfg *mi_cfg = &panel->mi_cfg;

	mi_cfg->dsi_panel = panel;

	mi_cfg->bl_is_big_endian= utils->read_bool(utils->data,
			"mi,mdss-dsi-bl-dcs-big-endian-type");

	rc = utils->read_u64(utils->data, "mi,panel-id", &mi_cfg->panel_id);
	if (rc) {
		mi_cfg->panel_id = 0;
		DISP_INFO("mi,panel-id not specified\n");
	} else {
		DISP_INFO("mi,panel-id is 0x%llx\n", mi_cfg->panel_id);
	}

	mi_cfg->hbm_51_ctl_flag = utils->read_bool(utils->data, "mi,hbm-51-ctl-flag");
	if (mi_cfg->hbm_51_ctl_flag) {

		rc = utils->read_u32(utils->data, "mi,hbm-on-51-index", &mi_cfg->hbm_on_51_index);
		if (rc) {
			mi_cfg->hbm_on_51_index = -1;
			DISP_INFO("mi,hbm-on-51-index not specified\n");
		} else {
			DISP_INFO("mi,hbm-on-51-index is %d\n", mi_cfg->hbm_on_51_index);
		}

		rc = utils->read_u32(utils->data, "mi,hbm-off-51-index", &mi_cfg->hbm_off_51_index);
		if (rc) {
			mi_cfg->hbm_off_51_index = -1;
			DISP_INFO("mi,hbm-off-51-index not specified\n");
		} else {
			DISP_INFO("mi,hbm-off-51-index is %d\n", mi_cfg->hbm_off_51_index);
		}

		rc = utils->read_u32(utils->data, "mi,hbm-fod-on-51-index", &mi_cfg->hbm_fod_on_51_index);
		if (rc) {
			mi_cfg->hbm_fod_on_51_index = -1;
			DISP_INFO("mi,hbm-fod-on-51-index not specified\n");
		} else {
			DISP_INFO("mi,hbm-fod-on-51-index is %d\n", mi_cfg->hbm_fod_on_51_index);
		}

		rc = utils->read_u32(utils->data, "mi,hbm-fod-off-51-index", &mi_cfg->hbm_fod_off_51_index);
		if (rc) {
			mi_cfg->hbm_fod_off_51_index = -1;
			DISP_INFO("mi,hbm-fod-off-51-index not specified\n");
		} else {
			DISP_INFO("mi,hbm-fod-off-51-index is %d\n", mi_cfg->hbm_fod_off_51_index);
		}

		rc = utils->read_u32(utils->data, "mi,hbm-fod-bl-level", &mi_cfg->hbm_fod_bl_lvl);
		if (rc) {
			mi_cfg->hbm_fod_bl_lvl = DEFAULT_HBM_BL_MAX_LEVEL;
			DISP_INFO("mi,hbm-fod-bl-level not specified, default:%d\n", DEFAULT_HBM_BL_MAX_LEVEL);
		} else {
			DISP_INFO("mi,hbm-fod-bl-level is %d\n", mi_cfg->hbm_fod_bl_lvl);
		}

		rc = utils->read_u32(utils->data, "mi,hbm-bl-min-level", &mi_cfg->hbm_bl_min_lvl);
		if (rc) {
			mi_cfg->hbm_bl_min_lvl = DEFAULT_HBM_BL_MIN_LEVEL;
			DISP_INFO("mi,hbm-bl-min-level not specified, default:%d\n", DEFAULT_HBM_BL_MIN_LEVEL);
		} else {
			DISP_INFO("mi,hbm-bl-min-level is %d\n", mi_cfg->hbm_bl_min_lvl);
		}

		rc = utils->read_u32(utils->data, "mi,hbm-bl-max-level", &mi_cfg->hbm_bl_max_lvl);
		if (rc) {
			mi_cfg->hbm_bl_max_lvl = DEFAULT_HBM_BL_MAX_LEVEL;
			DISP_INFO("mi,hbm-bl-max-level not specified, default:%d\n", DEFAULT_HBM_BL_MAX_LEVEL);
		} else {
			DISP_INFO("mi,hbm-bl-max-level is %d\n", mi_cfg->hbm_bl_max_lvl);
		}
	}

	rc = utils->read_u32(utils->data, "mi,panel-on-dimming-delay", &mi_cfg->panel_on_dimming_delay);
	if (rc) {
		mi_cfg->panel_on_dimming_delay = 0;
		DISP_INFO("mi,panel-on-dimming-delay not specified\n");
	} else {
		DISP_INFO("mi,panel-on-dimming-delay is %d\n", mi_cfg->panel_on_dimming_delay);
	}

	mi_cfg->gamma_update_flag = utils->read_bool(utils->data, "mi,mdss-dsi-panel-gamma-update-flag");
	if (mi_cfg->gamma_update_flag) {
		DISP_INFO("mi,mdss-dsi-panel-gamma-update-flag feature is defined\n");
		rc = mi_dsi_panel_parse_gamma_config(panel);
		if (rc)
			DISP_INFO("failed to parse gamma config\n");
	} else {
		DISP_INFO("mi,mdss-dsi-panel-gamma-update-flag feature not defined\n");
	}

	mi_cfg->aod_nolp_command_enabled = utils->read_bool(utils->data, "mi,aod-nolp-command-enabled");
	if (mi_cfg->aod_nolp_command_enabled) {
		DISP_INFO("mi aod-nolp-command-enabled\n");
	}

	mi_cfg->delay_before_fod_hbm_on = utils->read_bool(utils->data, "mi,delay-before-fod-hbm-on");
	if (mi_cfg->delay_before_fod_hbm_on) {
		DISP_INFO("delay before fod hbm on.\n");
	}

	mi_cfg->delay_before_fod_hbm_off = utils->read_bool(utils->data, "mi,delay-before-fod-hbm-off");
	if (mi_cfg->delay_before_fod_hbm_off) {
		DISP_INFO("delay before fod hbm off.\n");
	}

	mi_cfg->dfps_bl_ctrl = utils->read_bool(utils->data, "mi,mdss-dsi-panel-bl-dfps-enabled");
	if (mi_cfg->dfps_bl_ctrl) {
		rc = utils->read_u32(utils->data, "mi,mdss-dsi-panel-bl-dfps-switch-threshold", &mi_cfg->dfps_bl_threshold);
		if (rc) {
			mi_cfg->dfps_bl_threshold = 0;
			DISP_INFO("mi,mdss-dsi-panel-bl-dfps-switch-threshold\n");
		} else {
			DISP_INFO("mi,mdss-dsi-panel-bl-dfps-switch-threshold is %d\n", mi_cfg->dfps_bl_threshold);
		}
	}

	rc = utils->read_u32(utils->data, "mi,mdss-dsi-panel-dc-type", &mi_cfg->dc_type);
	if (rc) {
		mi_cfg->dc_type = 1;
		DISP_INFO("default dc backlight type is %d\n", mi_cfg->dc_type);
	} else {
		DISP_INFO("dc backlight type %d \n", mi_cfg->dc_type);
	}

	mi_cfg->aod_bl_51ctl = utils->read_bool(utils->data, "mi,aod-bl-51ctl-flag");

	rc = utils->read_u32(utils->data, "mi,mdss-dsi-panel-dc-threshold", &mi_cfg->dc_threshold);
	if (rc) {
		mi_cfg->dc_threshold = 540;
		DISP_INFO("default dc backlight type is %d\n", mi_cfg->dc_threshold);
	} else {
		DISP_INFO("dc backlight type %d \n", mi_cfg->dc_threshold);
	}

	mi_cfg->local_hbm_enabled = utils->read_bool(utils->data, "mi,local-hbm-enabled");
	if (mi_cfg->local_hbm_enabled) {
		DISP_INFO("local_hbm_enabled\n");
	}
	if (mi_cfg->local_hbm_enabled) {
		rc = utils->read_u32(utils->data, "mi,local-hbm-on-1000nit-51-index", &mi_cfg->local_hbm_on_1000nit_51_index);
		if (rc) {
			mi_cfg->local_hbm_on_1000nit_51_index = -1;
			DISP_INFO("mi,local-hbm-on-1000nit-51-index not specified\n");
		} else {
			DISP_INFO("mi,local-hbm-on-1000nit-51-index is %d\n", mi_cfg->local_hbm_on_1000nit_51_index);
		}

		rc = utils->read_u32(utils->data, "mi,local-hbm-off-to-hbm-51-index", &mi_cfg->local_hbm_off_to_hbm_51_index);
		if (rc) {
			mi_cfg->local_hbm_off_to_hbm_51_index = -1;
			DISP_INFO("mi,local-hbm-off-to-hbm-51-index not specified\n");
		} else {
			DISP_INFO("mi,local-hbm-off-to-hbm-51-index is %d\n", mi_cfg->local_hbm_off_to_hbm_51_index);
		}
	}
	rc = utils->read_u32(utils->data, "mi,fod-low-brightness-clone-threshold", &mi_cfg->fod_low_brightness_clone_threshold);
	if (rc) {
		mi_cfg->fod_low_brightness_clone_threshold = 0;
	}
	DISP_INFO("fod_low_brightness_clone_threshold=%d\n", mi_cfg->fod_low_brightness_clone_threshold);

	rc = utils->read_u32(utils->data, "mi,fod-low-brightness-lux-threshold", &mi_cfg->fod_low_brightness_lux_threshold);
	if (rc) {
		mi_cfg->fod_low_brightness_lux_threshold = 0;
	}
	DISP_INFO("fod_low_brightness_lux_threshold=%d\n", mi_cfg->fod_low_brightness_lux_threshold);

	rc = utils->read_u32(utils->data, "mi,max-brightness-clone", &mi_cfg->max_brightness_clone);
	if (rc) {
		mi_cfg->max_brightness_clone = DEFAULT_MAX_BRIGHTNESS_CLONE;
	}
	DISP_INFO("max_brightness_clone=%d\n", mi_cfg->max_brightness_clone);

	return rc;
}

