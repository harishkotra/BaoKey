// BaoKey untrusted host.
//
// This firmware is the *hostile half* of the demo by construction: it owns the
// radio, the microphone, the speaker and the screen, and it is assumed to be
// compromised. Its only job is to carry a 42-byte request to the Dabao over
// I2C and show back whatever the Dabao says.
//
// Build with -DHOSTILE=1 to get the lying variant: it paints "APPROVED" no
// matter what the vault answered, and it replays the same request three times.
// The vault still refuses, and the signature it withholds is proof the refusal
// happened on the other chip — nothing on this board reports it.

#include <Arduino.h>
#include <Wire.h>
#include <Arduino_GFX_Library.h>

// The carrier's MAX98357 sits on I2S; the host can talk. Audio is output, not
// authority -- the vault never hears it.
#ifndef ENABLE_SPK
#define ENABLE_SPK 0
#endif

#if ENABLE_SPK
#include <driver/i2s.h>
#include "audio_clips.h"
#endif

#include "config.h"

#ifndef TRANSPORT_SERIAL
#define TRANSPORT_SERIAL 0
#endif

// The ST7789 panel is an optional add-on. When it is not wired, this must be 0
// or the board boot-loops before it ever prints a line: gfx->begin() runs
// before the USB/UART console is up, so a dead SPI bus resets the chip silently.
#ifndef ENABLE_LCD
#define ENABLE_LCD 0
#endif

// The carrier's MAX98357 sits on I2S; the host can talk. Audio is output, not
// authority -- the vault never hears it.
#ifndef ENABLE_SPK
#define ENABLE_SPK 0
#endif

#define ACT_LEN 42
#define REG_STATUS 0x00
#define REG_ACT 0x02
#define REG_RESP 0x40

static uint8_t regs[128];
static volatile uint8_t reg_ptr = 0;
static volatile bool resp_ready = false;

// The request currently on screen. Declared up here so the display code can
// render it; the vault never sees this copy, it parses the bytes itself.
static uint8_t last_act[ACT_LEN];
static bool have_act = false;

#if ENABLE_LCD
static Arduino_DataBus *bus = new Arduino_ESP32SPI(
    PIN_LCD_DC, PIN_LCD_CS, PIN_LCD_SCK, PIN_LCD_MOSI, GFX_NOT_DEFINED, HSPI);
static Arduino_GFX *gfx = new Arduino_ST7789(bus, PIN_LCD_RES, 0 /* rotation */, true, 240, 240);
#endif

#if ENABLE_SPK
static bool spk_up = false;

static void spk_begin() {
  i2s_config_t cfg = {};
  cfg.mode = (i2s_mode_t)(I2S_MODE_MASTER | I2S_MODE_TX);
  cfg.sample_rate = SPK_RATE;
  cfg.bits_per_sample = I2S_BITS_PER_SAMPLE_16BIT;
  cfg.channel_format = I2S_CHANNEL_FMT_ONLY_LEFT;
  cfg.communication_format = I2S_COMM_FORMAT_STAND_I2S;
  cfg.dma_buf_count = 6;
  cfg.dma_buf_len = 512;
  cfg.tx_desc_auto_clear = true;
  i2s_pin_config_t pins = {};
  pins.mck_io_num = I2S_PIN_NO_CHANGE;
  pins.bck_io_num = PIN_SPK_BCLK;
  pins.ws_io_num = PIN_SPK_LRCK;
  pins.data_out_num = PIN_SPK_DOUT;
  pins.data_in_num = I2S_PIN_NO_CHANGE;
  spk_up = (i2s_driver_install(I2S_NUM_0, &cfg, 0, NULL) == ESP_OK) &&
           (i2s_set_pin(I2S_NUM_0, &pins) == ESP_OK);
  Serial.printf("SPK %s\n", spk_up ? "up" : "failed");
}

static void speak(const int16_t *pcm, size_t n) {
  if (!spk_up || !pcm || !n) return;
  size_t off = 0;
  while (off < n) {
    size_t wrote = 0;
    if (i2s_write(I2S_NUM_0, pcm + off, (n - off) * sizeof(int16_t), &wrote,
                  portMAX_DELAY) != ESP_OK)
      break;
    if (!wrote) break;
    off += wrote / sizeof(int16_t);
  }
}
#endif

// ---------------------------------------------------------------------------
// I2C target: a flat 128-byte register file. The Dabao writes the register
// address first, then reads or writes consecutive bytes from there.
// ---------------------------------------------------------------------------

void onReceive(int len) {
  if (len <= 0) return;
  uint8_t i = 0;
  while (Wire.available()) {
    uint8_t b = Wire.read();
    if (i == 0) {
      reg_ptr = b;
    } else {
      uint8_t a = reg_ptr + (i - 1);
      if (a < sizeof(regs)) regs[a] = b;
    }
    i++;
  }
  if (reg_ptr == REG_STATUS && len > 1 && regs[REG_STATUS] == 0) {
    // the Dabao clearing the request slot means its answer is in the window
    resp_ready = true;
  }
}

void onRequest() {
  uint8_t n = 0;
  while (n < 32 && (uint8_t)(reg_ptr + n) < sizeof(regs)) {
    Wire.write(regs[reg_ptr + n]);
    n++;
  }
}

// ---------------------------------------------------------------------------

static void text_at(const char *s_, int x, int y, uint16_t color, uint8_t size) {
#if ENABLE_LCD
  gfx->setTextSize(size);
  gfx->setTextColor(color);
  gfx->setCursor(x, y);
  gfx->print(s_);
#else
  (void)s_; (void)x; (void)y; (void)color; (void)size;
#endif
}

static void draw_header() {
#if ENABLE_LCD
  gfx->fillScreen(BLACK);
  text_at("BAOKEY", 8, 6, WHITE, 2);
  text_at(HOSTILE ? "S3 host: lying" : "S3 host: honest", 132, 12, 0x7BEF, 1);
  gfx->drawFastHLine(8, 30, 224, 0x7BEF);
#endif
}

static void center_text(const char *s_, int y, uint16_t color, uint8_t size) {
#if ENABLE_LCD
  gfx->setTextSize(size);
  gfx->setTextColor(color);
  int16_t x1, y1;
  uint16_t w, h;
  gfx->getTextBounds(s_, 0, 0, &x1, &y1, &w, &h);
  gfx->setCursor((240 - (int)w) / 2, y);
  gfx->print(s_);
#else
  (void)s_; (void)y; (void)color; (void)size;
#endif
}

// 0.050000 -> "0.05", without pulling in floating point printf on a chip that
// should stay integer-only.
static void fmt_eth(uint64_t wei, char *out, size_t n) {
  uint64_t whole = wei / 1000000000000000000ull;
  uint64_t frac = wei % 1000000000000000000ull;
  char f[19];
  snprintf(f, sizeof(f), "%018llu", (unsigned long long)frac);
  int last = 17;
  while (last >= 0 && f[last] == '0') last--;
  f[last + 1] = 0;
  if (last < 0) snprintf(out, n, "%llu", (unsigned long long)whole);
  else snprintf(out, n, "%llu.%s", (unsigned long long)whole, f);
}

static void show_request() {
#if ENABLE_LCD
  if (!have_act) {
    text_at("no request yet", 8, 46, 0x7BEF, 1);
    return;
  }
  uint8_t op = last_act[1];
  uint64_t wei = 0;
  for (int i = 7; i >= 0; i--) wei = (wei << 8) | last_act[2 + i];
  uint32_t nonce = 0;
  for (int i = 3; i >= 0; i--) nonce = (nonce << 8) | last_act[30 + i];

  char amt[28], line[40];
  if (op == 2) {
    fmt_eth(wei, amt, sizeof(amt));
    snprintf(line, sizeof(line), "%s ETH", amt);
    text_at(line, 8, 40, WHITE, 3);
  } else {
    text_at("LOGIN", 8, 40, WHITE, 3);
  }
  snprintf(line, sizeof(line), "to 0x%02x%02x..%02x%02x", last_act[10], last_act[11],
           last_act[28], last_act[29]);
  text_at(line, 8, 76, 0xD69A, 1);
  snprintf(line, sizeof(line), "nonce %lu   op %u   ver %u", (unsigned long)nonce, op,
           last_act[0]);
  text_at(line, 8, 92, 0xD69A, 1);
  gfx->drawFastHLine(8, 112, 224, 0x4208);
#endif
}

static void show_waiting() {
  draw_header();
  show_request();
  center_text("waiting for the vault", 150, 0xFFE0, 1);
}

static void show_result(uint8_t rc, const char *text) {
  draw_header();
  show_request();
  bool allow = (rc == 0);
#if HOSTILE
  // The lie: the host paints success no matter what the vault answered. A
  // judge cannot tell from this screen which of the two happened -- that is
  // exactly why the receipt exists.
  allow = true;
#endif
  center_text(allow ? "APPROVED" : "REFUSED", 140, allow ? GREEN : RED, 3);
#if ENABLE_LCD
  if (allow) {
    text_at("signed", 8, 190, 0x07E0, 1);
  } else {
    char why[40];
    snprintf(why, sizeof(why), "vault said: %s", text && text[0] ? text : "no");
    text_at(why, 8, 190, RED, 1);
    text_at("the receipt is the truth", 8, 208, 0x7BEF, 1);
  }
#else
  (void)text;
#endif
}

// ---------------------------------------------------------------------------

static bool hex2(const char *s, uint8_t *out, size_t n) {
  for (size_t i = 0; i < n; i++) {
    char hi = s[2 * i], lo = s[2 * i + 1];
    auto v = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
    };
    int a = v(hi), b = v(lo);
    if (a < 0 || b < 0) return false;
    out[i] = (uint8_t)((a << 4) | b);
  }
  return true;
}

static void submit(const uint8_t *act, size_t n) {
  if (n > ACT_LEN) n = ACT_LEN;
  memcpy(last_act, act, n);
  have_act = true;
#if TRANSPORT_SERIAL
  // No wire to the Dabao: the request goes out over USB to the relay, which
  // hands it to the vault. The relay is a dumb pipe; it cannot sign anything.
  char hex[2 * ACT_LEN + 1];
  for (size_t i = 0; i < n; i++) sprintf(&hex[2 * i], "%02x", act[i]);
  hex[2 * n] = 0;
  show_waiting();
  Serial.printf("REQ %s\n", hex);
#else
  memset(regs, 0, sizeof(regs));
  memcpy(&regs[REG_ACT], act, n);
  regs[REG_STATUS] = 0x01;
  resp_ready = false;
  show_waiting();
#endif
}

static void deliver(uint8_t rc, const char *text) {
  Serial.printf("RES %u %s\n", rc, text);
  show_result(rc, text);
#if ENABLE_SPK
#if HOSTILE
  // Same lie, now audible. It says "approved" no matter what came back.
  speak(SPK_LIE, SPK_LIE_N);
#else
  if (rc == 0) speak(SPK_OK, SPK_OK_N);
  else speak(SPK_NO, SPK_NO_N);
#endif
#endif
#if HOSTILE
  // A hostile host does not take no for an answer: it re-submits the exact
  // same bytes. The vault rejects them as REPLAY, which is the point.
  static int replays = 0;
  if (rc != 0 && replays < 2) {
    replays++;
    delay(300);
    submit(last_act, ACT_LEN);
  } else {
    replays = 0;
    delay(1200);
    show_waiting();
  }
#endif
}

static void handle_serial() {
  static char line[320];
  static size_t len = 0;
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\r') continue;
    if (c != '\n') {
      if (len < sizeof(line) - 1) line[len++] = c;
      continue;
    }
    line[len] = 0;
    len = 0;
    if (strncmp(line, "ACT ", 4) == 0) {
      uint8_t act[ACT_LEN];
      if (!hex2(line + 4, act, ACT_LEN)) {
        Serial.println("RES 2 bad_hex");
        continue;
      }
      Serial.println("ACK");
      submit(act, ACT_LEN);
    } else if (strncmp(line, "RES ", 4) == 0) {
      uint8_t rc = (uint8_t)atoi(line + 4);
      const char *text = strchr(line + 4, ' ');
      deliver(rc, text ? text + 1 : "");
    } else if (strcmp(line, "PING") == 0) {
      Serial.println("PONG");
    } else if (strcmp(line, "STATUS") == 0) {
      Serial.printf("STATUS %s transport=%s\n", HOSTILE ? "hostile" : "honest",
                    TRANSPORT_SERIAL ? "serial" : "i2c");
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.printf("BAOKEY host up (%s) transport=%s\n", HOSTILE ? "HOSTILE" : "honest",
                TRANSPORT_SERIAL ? "serial" : "i2c");
  Serial.flush();

#if ENABLE_SPK
  spk_begin();
#endif

#if ENABLE_LCD
  pinMode(PIN_LCD_BLK, OUTPUT);
  digitalWrite(PIN_LCD_BLK, HIGH);
  gfx->begin(40000000);
  draw_header();
  center_text("booting", 100, WHITE, 2);
#endif

  memset(regs, 0, sizeof(regs));
#if !TRANSPORT_SERIAL
  Wire.begin(I2C_TARGET_ADDR, PIN_I2C_SDA, PIN_I2C_SCL, 100000);
  Wire.onReceive(onReceive);
  Wire.onRequest(onRequest);
#endif

  Serial.printf("BAOKEY host up (%s) transport=%s\n", HOSTILE ? "HOSTILE" : "honest",
                TRANSPORT_SERIAL ? "serial" : "i2c");
  show_waiting();
}

void loop() {
  handle_serial();

#if !TRANSPORT_SERIAL
  if (resp_ready) {
    resp_ready = false;
    uint8_t rc = regs[REG_RESP];
    uint8_t n = regs[REG_RESP + 1];
    if (n > 60) n = 60;
    char text[64];
    memcpy(text, &regs[REG_RESP + 2], n);
    text[n] = 0;
    deliver(rc, text);
  }
#endif

  delay(10);
}
