/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 * Copyright (C) 2020 XiaoMi, Inc.
 */

#ifndef _MI_DSI_PANEL_H_
#define _MI_DSI_PANEL_H_

#include <linux/types.h>

#include <drm/mi_disp.h>

#include "dsi_panel.h"
#include "dsi_defs.h"
#include "mi_disp_feature.h"

enum bkl_dimming_state {
	STATE_NONE,
	STATE_DIM_BLOCK,
	STATE_DIM_RESTORE,
	STATE_ALL
};

/* 90Hz gamma and 144Hz gamma info */
struct gamma_cfg {
	bool read_done;
	/* 144Hz gamma info */
	u8 otp_read_b8[44];
	u8 otp_read_b9[237];
	u8 otp_read_ba[63];

	u32 flash_read_total_param;
	u64 gamma_checksum;
	u8 flash_gamma_read[346];
	/* 90Hz gamma info */
	u8 flash_read_b8[44];
	u8 flash_read_b9[237];
	u8 flash_read_ba[63];
	u8 flash_read_checksum[2];

	u32 update_b8_index;
	u32 update_b9_index;
	u32 update_ba_index;

	bool update_done_90hz;
	bool update_done_144hz;
};

/* Panel flag need update when panel power state changed*/
enum panel_flag_update {
	PANEL_OFF,
	PANEL_ON,
	PANEL_LP1,
	PANEL_LP2,
	PANEL_NOLP,
	PANEL_MAX
};

struct mi_dsi_panel_cfg {
	struct dsi_panel *dsi_panel;

	/* xiaomi panel id */
	u64 panel_id;

	/* xiaomi feature values */
	int feature_val[DISP_FEATURE_MAX];

	/* bl_is_big_endian indicate brightness value
	 * high byte to 1st parameter, low byte to 2nd parameter
	 * eg: 0x51 { 0x03, 0xFF } ->
	 * u8 payload[2] = { brightness >> 8, brightness & 0xff}
	 */
	bool bl_is_big_endian;
	u32 last_bl_level;

	/* indicate refresh frequency Fps gpio */
	int disp_rate_gpio;

	/* gamma read */
	bool gamma_update_flag;
	struct gamma_cfg gamma_cfg;

	/* indicate esd check gpio and config irq */
	int esd_err_irq_gpio;
	int esd_err_irq;
	int esd_err_irq_flags;
	bool esd_err_enabled;

	u32 doze_brightness;
	/* Some panel nolp command is different according to current doze brightness set,
	 * But sometimes doze brightness change to DOZE_TO_NORMAL before nolp. So this
	 * doze_brightness_backup will save doze_brightness and only change to DOZE_TO_NORMAL by nolp.
	 */
	u32 doze_brightness_backup;

	bool hbm_51_ctl_flag;
	int hbm_on_51_index;
	int hbm_off_51_index;
	int hbm_fod_on_51_index;
	int hbm_fod_off_51_index;
	int hbm_fod_bl_lvl;
	int hbm_bl_min_lvl;
	int hbm_bl_max_lvl;

	bool in_fod_calibration;

	u32 panel_on_dimming_delay;

	/* AOD Nolp code customized*/
	bool aod_nolp_command_enabled;

	bool fod_hbm_layer_enabled;
	u32 fod_ui_ready;

	bool delay_before_fod_hbm_on;
	bool delay_before_fod_hbm_off;

	u32 dimming_state;

	bool aod_bl_51ctl;
	bool dfps_bl_ctrl;
	u32 dfps_bl_threshold;

	u32 dc_type;
	u32 dc_threshold;
	u32 brightness_clone;
	u32 real_brightness_clone;
	u32 max_brightness_clone;
	u32 thermal_max_brightness_clone;

	bool local_hbm_enabled;
	int local_hbm_on_1000nit_51_index;
	int local_hbm_off_to_hbm_51_index;
	u32 fod_low_brightness_clone_threshold;
	u32 fod_low_brightness_lux_threshold;
	int local_hbm_target;
};

struct dsi_read_config {
	bool is_read;
	struct dsi_panel_cmd_set read_cmd;
	u32 cmds_rlen;
	u8 rbuf[256];
};

extern struct dsi_read_config g_dsi_read_cfg;

bool is_aod_and_panel_initialized(struct dsi_panel *panel);

bool is_support_mi_aod_nolp_command(struct dsi_panel *panel);

bool is_backlight_set_skip(struct dsi_panel *panel, u32 bl_lvl);

bool is_hbm_fod_on(struct dsi_panel *panel);

int mi_dsi_panel_esd_irq_ctrl(struct dsi_panel *panel,
			bool enable);

int mi_dsi_panel_write_cmd_set(struct dsi_panel *panel,
			struct dsi_panel_cmd_set *cmd_sets);

int mi_dsi_panel_read_cmd_set(struct dsi_panel *panel,
			struct dsi_read_config *read_config);

int mi_dsi_panel_write_mipi_reg(struct dsi_panel *panel,
			char *buf);

ssize_t mi_dsi_panel_read_mipi_reg(struct dsi_panel *panel,
			char *buf, size_t size);

int mi_dsi_panel_read_gamma_param(struct dsi_panel *panel);

int mi_dsi_panel_update_gamma_param(struct dsi_panel *panel);

ssize_t mi_dsi_panel_print_gamma_param(struct dsi_panel *panel,
			char *buf, size_t size);

int mi_dsi_panel_set_disp_param(struct dsi_panel *panel,
			struct disp_feature_ctl *ctl);

ssize_t mi_dsi_panel_get_disp_param(struct dsi_panel *panel,
			char *buf, size_t size);

int mi_dsi_panel_set_doze_brightness(struct dsi_panel *panel,
			u32 doze_brightness);

int mi_dsi_panel_get_doze_brightness(struct dsi_panel *panel,
			u32 *doze_brightness);

int mi_dsi_panel_get_brightness(struct dsi_panel *panel,
			u32 *brightness);

int mi_dsi_panel_write_dsi_cmd(struct dsi_panel *panel,
			struct dsi_cmd_rw_ctl *ctl);

int mi_dsi_panel_write_dsi_cmd_set(struct dsi_panel *panel, int type);

ssize_t mi_dsi_panel_show_dsi_cmd_set_type(struct dsi_panel *panel,
			char *buf, size_t size);

void mi_dsi_panel_update_last_bl_level(struct dsi_panel *panel,
			int brightness);

void mi_dsi_update_micfg_flags(struct dsi_panel *panel,
			int power_mode);

int mi_dsi_panel_nolp(struct dsi_panel *panel);

void mi_dsi_dc_mode_enable(struct dsi_panel *panel,
			bool enable);

int mi_dsi_fps_switch(struct dsi_panel *panel);

int mi_dsi_panel_set_brightness_clone(struct dsi_panel *panel,
			u32 brightness_clone);

int mi_dsi_panel_get_brightness_clone(struct dsi_panel *panel,
			u32 *brightness_clone);

#endif /* _MI_DSI_PANEL_H_ */
