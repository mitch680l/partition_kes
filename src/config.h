#define GPS_READ_BUFFER_SIZE 126  
#define GPS_STARTUP_DELAY_MS 2000  
#define GPS_CONFIG_TIMEOUT_MS 500  
#define GPS_MAX_CONFIG_ATTEMPTS 3
#define M10S_ADDR 0x42
#define NAV_PVT_LEN 92

#define MQTT_MAX_STR_LEN 128
#define MQTT_THREAD_STACK_SIZE 2048
#define MQTT_THREAD_PRIORITY 1
#define JSON_BUF_SIZE 516
#define BAD_PUBLISH_LIMIT 5
#define MQTT_RECONNECT_DELAY_SEC 10


#define MAX_INPUT_LEN 256
#define BLOB_HEADER_SIZE 0
#define ENTRY_SIZE 128

#define MAX_ENTRIES         16
#define MAX_IV_LEN          16
#define MAX_AAD_LEN         64
#define MAX_CIPHERTEXT_LEN  256
#define FLASH_PAGE_SIZE  4096 
#define ENTRIES_PER_PAGE (FLASH_PAGE_SIZE / ENTRY_SIZE)
#define CONFIG_PAGE_COUNT 2  
#define TOTAL_ENTRIES     (CONFIG_PAGE_COUNT * ENTRIES_PER_PAGE) 
#define ENCRYPTED_BLOB_ADDR ((const uint8_t *)0xfb000)
#define ENCRYPTED_BLOB_SIZE 8192 
#define FLASH_CRC_PAGE_OFFSET (CONFIG_PAGE_COUNT * FLASH_PAGE_SIZE)
#define FLASH_PAGE_CRC_SIZE  (ENCRYPTED_BLOB_SIZE - FLASH_CRC_PAGE_OFFSET)
#define CRC_LOCATION_OFFSET (ENCRYPTED_BLOB_SIZE - 4)


#define PROVISIONING_SUCCESS            (0)
#define PROVISIONING_ERROR_CRYPTO_INIT  (-100)
#define PROVISIONING_ERROR_KEY_IMPORT   (-101)
#define PROVISIONING_ERROR_KEY_OPEN     (-102)
#define PROVISIONING_ERROR_ENCRYPT      (-103)
#define PROVISIONING_ERROR_DECRYPT      (-104)
#define PROVISIONING_ERROR_IV_GEN       (-105)
#define PROVISIONING_ERROR_VERIFICATION (-106)
#define PROVISIONING_ERROR_KEY_DESTROY  (-107)
#define PROVISIONING_ERROR_BUFFER_SIZE  (-108)

#define NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE (100)
#define NRF_CRYPTO_EXAMPLE_AES_BLOCK_SIZE (16)
#define NRF_CRYPTO_EXAMPLE_AES_IV_SIZE (12)
#define NRF_CRYPTO_EXAMPLE_AES_ADDITIONAL_SIZE (35)
#define NRF_CRYPTO_EXAMPLE_AES_GCM_TAG_LENGTH (16)
#define AES_KEY_SIZE (32) 
#define DECRYPTED_OUTPUT_MAX 256



extern char mqtt_client_id[MQTT_MAX_STR_LEN];               
extern int  mqtt_broker_port;
extern int interval_mqtt;
extern int fota_interval_ms;
extern int gps_target_rate;
extern char firmware_filename[MQTT_MAX_STR_LEN];
extern char json_payload[512];


extern const char *mqtt_broker_host;
extern const char *fota_host; 
extern struct mqtt_utf8 struct_pass;
extern struct mqtt_utf8 struct_user;

void set_user_pass(void);
void clear_user_pass(void);
void config_init();
