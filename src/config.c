#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <zephyr/logging/log.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/random/random.h>
#include <nrf_modem_at.h>
#include "shell_commands.h"
#include <dk_buttons_and_leds.h>
#include <modem/modem_key_mgmt.h>

#include "shell_commands.h"
LOG_MODULE_REGISTER(configuration, LOG_LEVEL_INF);
char json_payload[512] = "NO PVT";
char sensor_payload[512] = "NO SENSOR DATA";
char lte_payload[512] = "NO LTE DATA";
char topic_gps[64];
char topic_sensor[64];
char topic_lte[64];

struct mqtt_utf8 struct_pass;
struct mqtt_utf8 struct_user;
system_enable_t sys_enable_config;

mqtt_config_t *mqtt_config = NULL;
ota_config_t *ota_config = NULL;

void parse_system_enable_config(void) {
    memset(&sys_enable_config, 0, sizeof(sys_enable_config));

    const char *raw = get_config("sys_en");
    if (!raw) {
        return;
    }

    // Parse hex string like "0x01FF"
    uint16_t bitmask = (uint16_t)strtol(raw, NULL, 0);

    sys_enable_config.lte_en        = bitmask & SYS_EN_LTE_EN;
    sys_enable_config.irid_en       = bitmask & SYS_EN_IRID_EN;
    sys_enable_config.psm_en        = bitmask & SYS_EN_PSM_EN;
    sys_enable_config.hw_en         = bitmask & SYS_EN_HW_EN;
    sys_enable_config.mdm_en        = bitmask & SYS_EN_MDM_EN;
    sys_enable_config.gnss_en       = bitmask & SYS_EN_GNSS_EN;
    sys_enable_config.imu_en        = bitmask & SYS_EN_IMU_EN;
    sys_enable_config.comp_en       = bitmask & SYS_EN_COMP_EN;
    sys_enable_config.baro_en       = bitmask & SYS_EN_BARO_EN;
    sys_enable_config.mqtt_en       = bitmask & SYS_EN_MQTT_EN;
    sys_enable_config.ota_en        = bitmask & SYS_EN_OTA_EN;
    sys_enable_config.debug_mode    = bitmask & SYS_EN_DEBUG_MODE;
    sys_enable_config.factory_mode  = bitmask & SYS_EN_FACTORY_MODE;
}

void parse_mqtt_config(mqtt_config_t *cfg) {
    const char *val;
    val = get_config("mq_rt");
    if (val) cfg->publish_rate = atoi(val);
    val = get_config("mq_addr");
    if (val) strncpy(cfg->broker_addr, val, sizeof(cfg->broker_addr) - 1);
    val = get_config("mq_port");
    if (val) cfg->broker_port = atoi(val);
    val = get_config("mq_clid");
    if (val) strncpy(cfg->client_id, val, sizeof(cfg->client_id) - 1);
    val = get_config("mq_user");
    if (val) strncpy(cfg->username, val, sizeof(cfg->username) - 1);
    val = get_config("mq_pass");
    if (val) strncpy(cfg->password, val, sizeof(cfg->password) - 1);
    val = get_config("mq_tls");
    if (val) cfg->tls_enabled = atoi(val) ? true : false;
    val = get_config("mq_qos");
    if (val) cfg->qos = atoi(val);
}

void parse_ota_config(ota_config_t *cfg) {
    const char *val;
    val = get_config("ota_int");
    if (val) cfg->check_interval = atoi(val);
    val = get_config("ota_addr");
    if (val) strncpy(cfg->server_addr, val, sizeof(cfg->server_addr) - 1);
    val = get_config("ota_port");
    if (val) cfg->server_port = atoi(val);
    val = get_config("ota_user");
    if (val) strncpy(cfg->username, val, sizeof(cfg->username) - 1);
    val = get_config("ota_pass");
    if (val) strncpy(cfg->password, val, sizeof(cfg->password) - 1);
    val = get_config("ota_tls");
    if (val) cfg->tls_enabled = atoi(val) ? true : false;
    val = get_config("ota_cert");
    if (val) strncpy(cfg->cert_tag, val, sizeof(cfg->cert_tag) - 1);
}



void print_ota_config(void) {
    if (!ota_config) {
        printf("OTA config not initialized.\n");
        return;
    }

    printf("=== OTA Configuration ===\n");
    printf("Check Interval: %d\n", ota_config->check_interval);
    printf("Server Addr:    %s\n", ota_config->server_addr);
    printf("Server Port:    %d\n", ota_config->server_port);
    printf("Username:       %s\n", ota_config->username);
    printf("Password:       %s\n", ota_config->password);
    printf("TLS Enabled:    %s\n", ota_config->tls_enabled ? "Yes" : "No");
    printf("Cert Tag:       %s\n", ota_config->cert_tag);
}

void print_mqtt_config(void) {
    if (!mqtt_config) {
        printf("MQTT config not initialized.\n");
        return;
    }

    printf("=== MQTT Configuration ===\n");
    printf("Publish Rate:  %d\n", mqtt_config->publish_rate);
    printf("Broker Addr:   %s\n", mqtt_config->broker_addr);
    printf("Broker Port:   %d\n", mqtt_config->broker_port);
    printf("Client ID:     %s\n", mqtt_config->client_id);
    printf("Username:      %s\n", mqtt_config->username);
    printf("Password:      %s\n", mqtt_config->password);
    printf("TLS Enabled:   %s\n", mqtt_config->tls_enabled ? "Yes" : "No");
    printf("QoS:           %d\n", mqtt_config->qos);
}

void config_init(void) {
    parse_system_enable_config();  // ← MUST run first

    if (sys_enable_config.mqtt_en) {
        mqtt_config = malloc(sizeof(mqtt_config_t));
        if (mqtt_config != NULL) {
            memset(mqtt_config, 0, sizeof(mqtt_config_t));
            parse_mqtt_config(mqtt_config);
        } else {
            printk("MQTT config allocation failed\n");
        }
    }

    if (sys_enable_config.ota_en) {
        ota_config = malloc(sizeof(ota_config_t));
        if (ota_config != NULL) {
            memset(ota_config, 0, sizeof(ota_config_t));
            parse_ota_config(ota_config);
        } else {
            printk("OTA config allocation failed\n");
        }
    }
}