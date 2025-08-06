#pragma once

#include <zephyr/device.h>
#include <zephyr/drivers/i2c.h>

//
// ┌────────────────────────────┐
// │ REGISTER ADDRESSES         │
// └────────────────────────────┘
//

#define KTD2026_REG_EN_RST         0x00  // Reg0: Enable/Reset control
#define KTD2026_REG_FLASH_PERIOD   0x01  // Reg1: Flash period + ramp mode
#define KTD2026_REG_FLASH_ON1      0x02  // Reg2: LED1 flash ON time
#define KTD2026_REG_FLASH_ON2      0x03  // Reg3: LED2 flash ON time
#define KTD2026_REG_CH_CTRL        0x04  // Reg4: LED channel mode control
#define KTD2026_REG_RAMP_RATE      0x05
#define KTD2026_REG_LED1_IOUT      0x06
#define KTD2026_REG_LED2_IOUT      0x07
#define KTD2026_REG_LED3_IOUT      0x08
// Note: Reg9 unused (you mentioned only 3 LEDs)

// Default I2C address for KTD2026
#define KTD2026_I2C_ADDR           0x30

//
// ┌────────────────────────────┐
// │ DEVICE STRUCTURE           │
// └────────────────────────────┘
//

struct ktd2026_device {
    const struct device *i2c_dev;
    uint16_t i2c_addr;
};

//
// ┌────────────────────────────┐
// │ REG0 CONTROL BITFIELDS     │
// └────────────────────────────┘
//

// Reset / Timer Slot Control (Reg0[2:0])
enum ktd2026_reset_mode {
    KTD2026_TSLOT1              = 0b000,
    KTD2026_TSLOT2              = 0b001,
    KTD2026_TSLOT3              = 0b010,
    KTD2026_TSLOT4              = 0b011,
    KTD2026_RST_NONE            = 0b100,
    KTD2026_RST_REGISTERS       = 0b101,
    KTD2026_RST_DIGITAL_ONLY    = 0b110,
    KTD2026_RST_CHIP            = 0b111,
};

// Enable Control (Reg0[4:3])
#define KTD2026_EN_CTRL_SCL_SDA_HIGH     (0b00 << 3)
#define KTD2026_EN_CTRL_SCL_SDA_TOGGLE   (0b01 << 3)
#define KTD2026_EN_CTRL_SCL_HIGH         (0b10 << 3)
#define KTD2026_EN_CTRL_ALWAYS_ON        (0b11 << 3)

// Rise/Fall Time Scaling (Reg0[6:5])
#define KTD2026_RF_SCALE_1X_NORMAL       (0b00 << 5)
#define KTD2026_RF_SCALE_2X_SLOWER       (0b01 << 5)
#define KTD2026_RF_SCALE_4X_SLOWER       (0b10 << 5)
#define KTD2026_RF_SCALE_8X_FASTER       (0b11 << 5)

//
// ┌────────────────────────────┐
// │ REG1 CONTROL               │
// └────────────────────────────┘
//

// Flash ramp mode (Reg1[7])
enum ktd2026_ramp_mode {
    KTD2026_RAMP_LINEAR = 0,
    KTD2026_RAMP_LOG    = 1
};

//
// ┌────────────────────────────┐
// │ REG4 LED MODE CONTROL      │
// └────────────────────────────┘
//

// Per-channel LED modes
enum ktd2026_led_mode {
    KTD2026_LED_OFF   = 0b00,
    KTD2026_LED_ON    = 0b01,
    KTD2026_LED_PWM1  = 0b10,
    KTD2026_LED_PWM2  = 0b11,
};

// LED Indexes (1-based)
#define KTD2026_LED1  1
#define KTD2026_LED2  2
#define KTD2026_LED3  3

//
// ┌────────────────────────────┐
// │ INITIALIZATION             │
// └────────────────────────────┘
//

/**
 * @brief Initialize KTD2026 device structure
 * 
 * @param ktd_dev Pointer to KTD2026 device structure
 * @param i2c_dev I2C device to use for communication
 * @param i2c_addr I2C address of the KTD2026 (default: 0x30)
 * @return 0 on success, negative error code on failure
 */
int ktd2026_init(struct ktd2026_device *ktd_dev, const struct device *i2c_dev, uint16_t i2c_addr);

//
// ┌────────────────────────────┐
// │ PER-REGISTER WRITE HELPERS │
// └────────────────────────────┘
//

int ktd2026_write_en_rst(struct ktd2026_device *ktd_dev, uint8_t val);
int ktd2026_write_flash_period(struct ktd2026_device *ktd_dev, uint8_t val);
int ktd2026_write_flash_on1(struct ktd2026_device *ktd_dev, uint8_t val);
int ktd2026_write_flash_on2(struct ktd2026_device *ktd_dev, uint8_t val);
int ktd2026_write_channel_ctrl(struct ktd2026_device *ktd_dev, uint8_t val);
int ktd2026_write_ramp_rate(struct ktd2026_device *ktd_dev, uint8_t val);
int ktd2026_write_led1_iout(struct ktd2026_device *ktd_dev, uint8_t val);
int ktd2026_write_led2_iout(struct ktd2026_device *ktd_dev, uint8_t val);
int ktd2026_write_led3_iout(struct ktd2026_device *ktd_dev, uint8_t val);

//
// ┌────────────────────────────┐
// │ REG0 MODE HELPERS          │
// └────────────────────────────┘
//

// Reset control helpers (Reg0[2:0])
int ktd2026_set_reset_mode(struct ktd2026_device *ktd_dev, enum ktd2026_reset_mode mode);
int ktd2026_select_timer_slot1(struct ktd2026_device *ktd_dev);
int ktd2026_select_timer_slot2(struct ktd2026_device *ktd_dev);
int ktd2026_select_timer_slot3(struct ktd2026_device *ktd_dev);
int ktd2026_select_timer_slot4(struct ktd2026_device *ktd_dev);
int ktd2026_reset_registers_only(struct ktd2026_device *ktd_dev);
int ktd2026_reset_digital_only(struct ktd2026_device *ktd_dev);
int ktd2026_reset_chip(struct ktd2026_device *ktd_dev);

// Enable control (Reg0[4:3])
int ktd2026_set_enable_control_scl_sda_high(struct ktd2026_device *ktd_dev);
int ktd2026_set_enable_control_scl_sda_toggle(struct ktd2026_device *ktd_dev);
int ktd2026_set_enable_control_scl_high(struct ktd2026_device *ktd_dev);
int ktd2026_set_enable_control_always_on(struct ktd2026_device *ktd_dev);

// Rise/fall scaling (Reg0[6:5])
int ktd2026_set_rise_fall_scale_1x(struct ktd2026_device *ktd_dev);
int ktd2026_set_rise_fall_scale_2x_slower(struct ktd2026_device *ktd_dev);
int ktd2026_set_rise_fall_scale_4x_slower(struct ktd2026_device *ktd_dev);
int ktd2026_set_rise_fall_scale_8x_faster(struct ktd2026_device *ktd_dev);

//
// ┌────────────────────────────┐
// │ REG1–3 FLASH TIMING        │
// └────────────────────────────┘
//

// Flash period + ramp mode (Reg1)
int ktd2026_set_flash_period(struct ktd2026_device *ktd_dev, float period_sec, enum ktd2026_ramp_mode ramp_mode);

// Flash ON time for LED1 / LED2 (Reg2 / Reg3)
int ktd2026_set_flash_on1(struct ktd2026_device *ktd_dev, float percent);
int ktd2026_set_flash_on2(struct ktd2026_device *ktd_dev, float percent);

//
// ┌────────────────────────────┐
// │ REG4 LED MODE CONTROL      │
// └────────────────────────────┘
//

int ktd2026_set_led_mode(struct ktd2026_device *ktd_dev, uint8_t led_index, enum ktd2026_led_mode mode);

//
// ┌────────────────────────────┐
// │ REG5 RAMP TIMES            │
// └────────────────────────────┘
//

int ktd2026_set_ramp_times(struct ktd2026_device *ktd_dev, uint8_t rise_index, uint8_t fall_index);

//
// ┌────────────────────────────┐
// │ REG6-8 LED CURRENT         │
// └────────────────────────────┘
//

int ktd2026_set_led_current(struct ktd2026_device *ktd_dev, uint8_t led_index, float current_ma);