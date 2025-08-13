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

mqtt_config_t     *mqtt_config     = NULL;
ota_config_t      *ota_config      = NULL;
hardware_info_t   *hw_info         = NULL;
modem_info_t      *modem_info      = NULL;
sensor_config_t   *sensor_config   = NULL;
gnss_config_t     *gnss_config     = NULL;
customer_info_t   *customer_info   = NULL;

void parse_hardware_info(hardware_info_t *cfg) {
    const char *val;

    val = get_config("hw_info");  // Format: ABC123456,1.2.3,2.1.0,1
    if (val) {
        sscanf(val, "%31[^,],%15[^,],%15[^,],%d", 
               cfg->sn, cfg->hw_ver, cfg->fw_ver, &cfg->uas_status);
    }

    val = get_config("pwr_st");
    if (val) {
        cfg->power_percent = atoi(val);
    }
}

void parse_modem_info(modem_info_t *cfg) {
    const char *val;

    val = get_config("mdm_info");  // Format: Quectel,QC789,1.4.2,status
    if (val) {
        sscanf(val, "%31[^,],%31[^,],%15[^,],%63[^,]", 
               cfg->make, cfg->model, cfg->fw_ver, cfg->topic);
    }

    val = get_config("mdm_imei");
    if (val) strncpy(cfg->imei, val, sizeof(cfg->imei) - 1);

    val = get_config("sim_info");  // Format: Verizon,AT&T
    if (val) {
        sscanf(val, "%31[^,],%31[^,]", cfg->sim, cfg->esim);
    }

    val = get_config("lte_bnd");
    if (val) {
        cfg->lte_bandmask = (uint16_t)strtol(val, NULL, 0);
    }
}


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

void parse_sensor_config(sensor_config_t *cfg) {
    const char *val;

    val = get_config("msg_fmt");
    if (val) strncpy(cfg->msg_format, val, sizeof(cfg->msg_format) - 1);
    else strncpy(cfg->msg_format, "JSON", sizeof(cfg->msg_format));

    val = get_config("gps_fmt");
    if (val) strncpy(cfg->gps_format, val, sizeof(cfg->gps_format) - 1);
    else strncpy(cfg->gps_format, "NMEA", sizeof(cfg->gps_format));

    val = get_config("units");
    if (val) strncpy(cfg->units, val, sizeof(cfg->units) - 1);
    else strncpy(cfg->units, "METRIC", sizeof(cfg->units));

    val = get_config("sens_rt");
    if (val) cfg->sampling_rate = atoi(val);
    else cfg->sampling_rate = 10;

    val = get_config("sens_flt");
    if (val) cfg->filter_window = atoi(val);
    else cfg->filter_window = 5;

    val = get_config("sens_cal");
    if (val) cfg->auto_calibrate = atoi(val) ? true : false;
    else cfg->auto_calibrate = false;
}

void parse_gnss_config(gnss_config_t *cfg) {
    const char *val;

    val = get_config("gnss_rt");
    if (val) cfg->update_rate = atoi(val);
    else cfg->update_rate = 1;

    val = get_config("gnss_ver");
    if (val) strncpy(cfg->version, val, sizeof(cfg->version) - 1);
    else strncpy(cfg->version, "u-blox8", sizeof(cfg->version));

    val = get_config("gnss_con");
    if (val) cfg->constellation_mask = (uint8_t)strtol(val, NULL, 0);
    else cfg->constellation_mask = 0x01;

    val = get_config("gnss_acc");
    if (val) cfg->accuracy_threshold = atoi(val);
    else cfg->accuracy_threshold = 3;
}

void parse_customer_info(customer_info_t *cfg) {
    const char *val;

    val = get_config("uas_num");
    if (val) strncpy(cfg->uas_num, val, sizeof(cfg->uas_num) - 1);

    val = get_config("cust_desc");
    if (val) strncpy(cfg->description, val, sizeof(cfg->description) - 1);

    val = get_config("cust_f1");
    if (val) strncpy(cfg->field1, val, sizeof(cfg->field1) - 1);

    val = get_config("cust_f2");
    if (val) strncpy(cfg->field2, val, sizeof(cfg->field2) - 1);

    val = get_config("cust_f3");
    if (val) strncpy(cfg->field3, val, sizeof(cfg->field3) - 1);

    val = get_config("cust_f4");
    if (val) strncpy(cfg->field4, val, sizeof(cfg->field4) - 1);
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

void print_system_enable(void) {
    printf("=== System Enable Flags ===\n");
    printf("LTE Enabled:         %s\n", sys_enable_config.lte_en        ? "Yes" : "No");
    printf("Iridium Enabled:     %s\n", sys_enable_config.irid_en       ? "Yes" : "No");
    printf("Power Save Mode:     %s\n", sys_enable_config.psm_en        ? "Yes" : "No");
    printf("HW Info Reporting:   %s\n", sys_enable_config.hw_en         ? "Yes" : "No");
    printf("Modem Info:          %s\n", sys_enable_config.mdm_en        ? "Yes" : "No");
    printf("GNSS Enabled:        %s\n", sys_enable_config.gnss_en       ? "Yes" : "No");
    printf("IMU Enabled:         %s\n", sys_enable_config.imu_en        ? "Yes" : "No");
    printf("Compass Enabled:     %s\n", sys_enable_config.comp_en       ? "Yes" : "No");
    printf("Barometer Enabled:   %s\n", sys_enable_config.baro_en       ? "Yes" : "No");
    printf("MQTT Enabled:        %s\n", sys_enable_config.mqtt_en       ? "Yes" : "No");
    printf("OTA Enabled:         %s\n", sys_enable_config.ota_en        ? "Yes" : "No");
    printf("Debug Mode:          %s\n", sys_enable_config.debug_mode    ? "Yes" : "No");
    printf("Factory Mode:        %s\n", sys_enable_config.factory_mode  ? "Yes" : "No");
}

void print_sensor_config(void) {
    if (!sensor_config) {
        printf("Sensor config not initialized.\n");
        return;
    }

    printf("=== Sensor Configuration ===\n");
    printf("Message Format:       %s\n", sensor_config->msg_format);
    printf("GPS Format:           %s\n", sensor_config->gps_format);
    printf("Units:                %s\n", sensor_config->units);
    printf("Sampling Rate (Hz):   %d\n", sensor_config->sampling_rate);
    printf("Filter Window Size:   %d\n", sensor_config->filter_window);
    printf("Auto Calibration:     %s\n", sensor_config->auto_calibrate ? "Enabled" : "Disabled");
}

void print_gnss_config(void) {
    if (!gnss_config) {
        printf("GNSS config not initialized.\n");
        return;
    }

    printf("=== GNSS Configuration ===\n");
    printf("Update Rate (Hz):     %d\n", gnss_config->update_rate);
    printf("Module Version:       %s\n", gnss_config->version);
    printf("Constellation Mask:   0x%02X\n", gnss_config->constellation_mask);
    printf("Accuracy Threshold:   %d meters\n", gnss_config->accuracy_threshold);
}
void print_hardware_info(void) {
    if (!hw_info) {
        printf("Hardware info not initialized.\n");
        return;
    }

    printf("=== Hardware Information ===\n");
    printf("Serial Number:        %s\n", hw_info->sn);
    printf("HW Version:           %s\n", hw_info->hw_ver);
    printf("FW Version:           %s\n", hw_info->fw_ver);
    printf("UAS Status:           %d\n", hw_info->uas_status);
    printf("Power Status:         %d%%\n", hw_info->power_percent);
}
void print_modem_info(void) {
    if (!modem_info) {
        printf("Modem info not initialized.\n");
        return;
    }

    printf("=== Modem Information ===\n");
    printf("Make:                 %s\n", modem_info->make);
    printf("Model:                %s\n", modem_info->model);
    printf("FW Version:           %s\n", modem_info->fw_ver);
    printf("Topic:                %s\n", modem_info->topic);
    printf("IMEI:                 %s\n", modem_info->imei);
    printf("SIM Provider:         %s\n", modem_info->sim);
    printf("eSIM Provider:        %s\n", modem_info->esim);
    printf("LTE Bandmask:         0x%04X\n", modem_info->lte_bandmask);
}

void print_customer_info(void) {
    if (!customer_info) {
        printf("Customer info not initialized.\n");
        return;
    }

    printf("=== Customer Information ===\n");
    printf("UAS Number:           %s\n", customer_info->uas_num);
    printf("Description:          %s\n", customer_info->description);
    printf("Custom Field 1:       %s\n", customer_info->field1);
    printf("Custom Field 2:       %s\n", customer_info->field2);
    printf("Custom Field 3:       %s\n", customer_info->field3);
    printf("Custom Field 4:       %s\n", customer_info->field4);
}

void print_all_configs(void) {
    
    print_hardware_info();
    print_modem_info();
    print_sensor_config();
    print_gnss_config();
    print_mqtt_config();
    print_ota_config();
    print_customer_info();
}

void config_init(void) {
    parse_system_enable_config();
    if (sys_enable_config.debug_mode) {
        print_system_enable();
    }
    if (sys_enable_config.hw_en) {
        hw_info = malloc(sizeof(hardware_info_t));
        if (hw_info) {
            memset(hw_info, 0, sizeof(*hw_info));
            parse_hardware_info(hw_info);
        }
    }

    if (sys_enable_config.mdm_en) {
        modem_info = malloc(sizeof(modem_info_t));
        if (modem_info) {
            memset(modem_info, 0, sizeof(*modem_info));
            parse_modem_info(modem_info);
        }
    }

    if (sys_enable_config.imu_en || sys_enable_config.comp_en || sys_enable_config.baro_en) {
        sensor_config = malloc(sizeof(sensor_config_t));
        if (sensor_config) {
            memset(sensor_config, 0, sizeof(*sensor_config));
            parse_sensor_config(sensor_config);
        }
    }

    if (sys_enable_config.gnss_en) {
        gnss_config = malloc(sizeof(gnss_config_t));
        if (gnss_config) {
            memset(gnss_config, 0, sizeof(*gnss_config));
            parse_gnss_config(gnss_config);
        }
    }

    if (sys_enable_config.mqtt_en) {
        mqtt_config = malloc(sizeof(mqtt_config_t));
        if (mqtt_config) {
            memset(mqtt_config, 0, sizeof(*mqtt_config));
            parse_mqtt_config(mqtt_config);
        }
    }

    if (sys_enable_config.ota_en) {
        ota_config = malloc(sizeof(ota_config_t));
        if (ota_config) {
            memset(ota_config, 0, sizeof(*ota_config));
            parse_ota_config(ota_config);
        }
    }

    customer_info = malloc(sizeof(customer_info_t));
    if (customer_info) {
        memset(customer_info, 0, sizeof(*customer_info));
        parse_customer_info(customer_info);
    }

    if (sys_enable_config.debug_mode) {
        print_all_configs();
    }
}

