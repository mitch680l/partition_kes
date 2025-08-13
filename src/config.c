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


static char user_buf[64];
static char pass_buf[64];


struct mqtt_utf8 struct_pass;
struct mqtt_utf8 struct_user;


void set_user_pass(void)
{
    LOG_INF("SETT USER PASS");
    const char *password = "NULL";
    const char *username = "NULL";
    //password = get_config("password");
    if (!password || strcmp(password, "NULL") == 0) {
        password = "Kalscott123";
    }
    strncpy(pass_buf, password, sizeof(pass_buf) - 1);
    pass_buf[sizeof(pass_buf) - 1] = '\0';

    //username = get_config("username");
    if (!username || strcmp(username, "NULL") == 0) {
        username = "admin";
    }
    strncpy(user_buf, username, sizeof(user_buf) - 1);
    user_buf[sizeof(user_buf) - 1] = '\0';

    LOG_INF("Setting MQTT username: %s", user_buf);
    LOG_INF("Setting MQTT password: %s", pass_buf);

    struct_pass.utf8 = (uint8_t *)pass_buf;
    struct_pass.size = strlen(pass_buf);
    struct_user.utf8 = (uint8_t *)user_buf;
    struct_user.size = strlen(user_buf);
}

void clear_user_pass(void)
{
    struct_pass.utf8 = NULL;
    struct_pass.size = 0;
    struct_user.utf8 = NULL;
    struct_user.size = 0;
    LOG_INF("Cleared MQTT username and password");
}



char mqtt_client_id[MQTT_MAX_STR_LEN] = "nrid";               
char firmware_filename[MQTT_MAX_STR_LEN];
char topic_gps[64];
char topic_sensor[64];
char topic_lte[64];
int  mqtt_broker_port = DEFAULT_MQTT_BROKER_PORT;
int interval_mqtt = DEFAULT_INTERVAL_MQTT;
int fota_interval_ms = DEFAULT_FOTA_INTERVAL_MS;
bool enable_iridium = DEFAULT_ENABLE_IRIDIUM;
int gps_target_rate = DEFAULT_GPS_TARGET_RATE;

char mqtt_broker_host[MQTT_MAX_STR_LEN] = "NULL";
char fota_host[MQTT_MAX_STR_LEN]        = "NULL";

static void load_str_config(const char *key, char *dest, size_t dest_size, const char *default_val, const char *label) {
    const char *val = get_config(key);
    if (val && strcmp(val, "NULL") != 0) {
        strncpy(dest, val, dest_size - 1);
        dest[dest_size - 1] = '\0';
        LOG_INF("Using configured %s: %s", label, dest);
    } else {
        strncpy(dest, default_val ? default_val : "", dest_size - 1);
        dest[dest_size - 1] = '\0';
        LOG_WRN("%s not found, using default: %s", key, dest);
    }
}

static void load_int_config(const char *key, int *dest, int default_val, const char *label) {
    const char *val = get_config(key);
    if (val && strcmp(val, "NULL") != 0) {
        *dest = atoi(val);
        LOG_INF("Using configured %s: %d", label, *dest);
    } else {
        *dest = default_val;
        LOG_WRN("%s not found, using default: %d", key, *dest);
    }
}

static void load_bool_config(const char *key, bool *dest, bool default_val, const char *label) {
    const char *val = get_config(key);
    if (val && strcmp(val, "NULL") != 0) {
        *dest = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
        LOG_INF("Using configured %s: %s", label, *dest ? "true" : "false");
    } else {
        *dest = default_val;
        LOG_WRN("%s not found, using default: %s", key, *dest ? "true" : "false");
    }
}

void config_init() {
    load_str_config("mqtt_broker_host", mqtt_broker_host, MQTT_MAX_STR_LEN, DEFAULT_BROKER_HOST, "MQTT broker");
    load_str_config("fota_host", fota_host, MQTT_MAX_STR_LEN, DEFAULT_FOTA_HOST, "FOTA host");
    load_str_config("mqtt_client_id", mqtt_client_id, MQTT_MAX_STR_LEN, "", "MQTT client ID");
    load_str_config("firmware_filename", firmware_filename, MQTT_MAX_STR_LEN, "", "firmware filename");
    load_str_config("topic_gps", topic_gps, sizeof(topic_gps), "", "GPS topic");
    load_str_config("topic_sensor", topic_sensor, sizeof(topic_sensor), "", "sensor topic");
    load_str_config("topic_lte", topic_lte, sizeof(topic_lte), "", "LTE topic");

    load_int_config("mqtt_broker_port", &mqtt_broker_port, mqtt_broker_port, "MQTT broker port");
    load_int_config("interval_mqtt", &interval_mqtt, interval_mqtt, "MQTT interval");
    load_int_config("fota_interval_ms", &fota_interval_ms, fota_interval_ms, "FOTA interval (ms)");
    load_bool_config("enable_iridium", &enable_iridium, enable_iridium, "Iridium enable");
    load_int_config("gps_target_rate", &gps_target_rate, gps_target_rate, "GPS target rate");
}