// Wiring for the untrusted host. Every one of these is on the S3 side of the
// trust boundary: if a pin here is cut, the Dabao still refuses to sign.
#pragma once

// --- I2C link to the Dabao (Dabao is master, this chip is target at 0x42) ---
#define PIN_I2C_SDA 8
#define PIN_I2C_SCL 9
#define I2C_TARGET_ADDR 0x42

// --- ST7789 1.54" 240x240 on the S3 expansion board's 8-pin header ---
// header order was: GND 3V3 SCL SDA RES DC CS BLK
// Taken from the carrier's own firmware for this exact board (Goouuu
// ESP32-S3 Smart Expansion Board V1.7): the 8-pin 1.54" header is hard-wired
// to these GPIOs, so the module plugs in and no jumpers are involved.
#define PIN_LCD_SCK 21
#define PIN_LCD_MOSI 47
#define PIN_LCD_CS 41
#define PIN_LCD_DC 40
#define PIN_LCD_RES 45
#define PIN_LCD_BLK 42

// --- MAX98357 I2S speaker on the carrier (PH2.0 connector) ---
#define PIN_SPK_DOUT 7
#define PIN_SPK_BCLK 15
#define PIN_SPK_LRCK 16
#define SPK_RATE 24000

// --- buttons on the carrier ---
#define PIN_BTN_A 0
#define PIN_BTN_B 38
#define PIN_BTN_C 39
