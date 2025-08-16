#include <stdio.h>
#include "fota.h"
#include <zephyr/kernel.h>
#include <zephyr/dfu/mcuboot.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/toolchain.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/shell/shell.h>
#include "config.h"
#include <dfu/dfu_target_mcuboot.h>
#include <modem/nrf_modem_lib.h>
#include <modem/lte_lc.h>
#include <modem/modem_key_mgmt.h>
#include <net/fota_download.h>
#include <nrf_socket.h>
// Configuration defines
#define CONFIG_DOWNLOAD_HOST "18.234.99.151"



enum fota_state { IDLE, CONNECTED, UPDATE_DOWNLOAD, UPDATE_PENDING, UPDATE_APPLY };
static enum fota_state state = IDLE;

static struct k_work fota_work;

static void fota_work_cb(struct k_work *work);
static void apply_state(enum fota_state new_state);
static int modem_configure_and_connect(void);
static int update_download(void);

/**
 * @brief Handler for LTE link control events
 */
static void lte_lc_handler(const struct lte_lc_evt *const evt)
{
	static bool connected;

	switch (evt->type) {
	case LTE_LC_EVT_NW_REG_STATUS:
		printk("LTE network registration status: %d\n", evt->nw_reg_status);
		
		if ((evt->nw_reg_status != LTE_LC_NW_REG_REGISTERED_HOME) &&
		    (evt->nw_reg_status != LTE_LC_NW_REG_REGISTERED_ROAMING)) {
			if (!connected) {
				break;
			}

			printk("LTE network is disconnected.\n");
			connected = false;
			if (state == CONNECTED || state == UPDATE_DOWNLOAD) {
				apply_state(IDLE);
			}
			break;
		}

		connected = true;

		if (state == IDLE) {
			printk("LTE Link Connected!\n");
			apply_state(CONNECTED);
		}
		break;
	
	case LTE_LC_EVT_PSM_UPDATE:
		printk("PSM parameter update: TAU: %d, Active time: %d\n", 
		       evt->psm_cfg.tau, evt->psm_cfg.active_time);
		break;
	case LTE_LC_EVT_RRC_UPDATE:
		printk("RRC mode update: %s\n", 
		       evt->rrc_mode == LTE_LC_RRC_MODE_CONNECTED ? "CONNECTED" : "IDLE");
		break;
	
	case LTE_LC_EVT_CELL_UPDATE:
		printk("Cell update: Cell ID: %d, TAC: %d\n", evt->cell.id, evt->cell.tac);
		break;
	
	case LTE_LC_EVT_LTE_MODE_UPDATE:
		printk("LTE mode update: %d\n", evt->lte_mode);
		break;

	default:
		printk("Unknown LTE event: %d\n", evt->type);
		break;
	}
}

static void apply_state(enum fota_state new_state)
{
	__ASSERT(state != new_state, "State already set: %d", state);

	state = new_state;

	switch (new_state) {
	case IDLE:
		modem_configure_and_connect();
		break;
	case CONNECTED:
		printk("LTE Connected - Starting FOTA download automatically\n");
		apply_state(UPDATE_DOWNLOAD);
		break;
	case UPDATE_DOWNLOAD:
		k_work_submit(&fota_work);
		break;
	case UPDATE_PENDING:
		printk("Update pending - applying automatically\n");
		apply_state(UPDATE_APPLY);
		break;
	case UPDATE_APPLY:
		k_work_submit(&fota_work);
		break;
	}
}

/**
 * @brief Configures modem to provide LTE link.
 */
static int modem_configure_and_connect(void)
{
	int err;

	printk("LTE Link Connecting ...\n");
	err = lte_lc_connect_async(lte_lc_handler);
	if (err) {
		printk("LTE link could not be established.");
		return err;
	}

	return 0;
}

static void fota_work_cb(struct k_work *work)
{
	int err;

	ARG_UNUSED(work);

	switch (state) {
	case UPDATE_DOWNLOAD:
		err = update_download();
		if (err) {
			printk("Download failed, err %d\n", err);
			apply_state(CONNECTED);
		}
		break;
	case UPDATE_APPLY:
		lte_lc_power_off();
		sys_reboot(SYS_REBOOT_WARM);
		break;
	default:
		break;
	}
}

static void fota_dl_handler(const struct fota_download_evt *evt)
{
	switch (evt->id) {
	case FOTA_DOWNLOAD_EVT_ERROR:
		printk("Received error from fota_download\n");
		apply_state(CONNECTED);
		break;
	case FOTA_DOWNLOAD_EVT_FINISHED:
		apply_state(UPDATE_PENDING);
		break;
	default:
		break;
	}
}

static int update_download(void)
{
	int err;

	err = fota_download_init(fota_dl_handler);
	if (err) {
		printk("fota_download_init() failed, err %d\n", err);
		return 0;
	}

	err = fota_download_start(CONFIG_DOWNLOAD_HOST, firmware_filename, atoi(ota_config.cert_tag), 0, 0);
	if (err) {
		printk("fota_download_start() failed, err %d\n", err);
		return err;
	}

	return 0;
}

int fota_init_and_start(void)
{
	int err;
	printk("HTTP application update sample started\n");

	/* This is needed so that MCUBoot won't revert the update. */
	boot_write_img_confirmed();


	k_work_init(&fota_work, fota_work_cb);

	err = modem_configure_and_connect();
	if (err) {
		printk("Modem configuration failed: %d\n", err);
		return err;
	}

	return 0;
}