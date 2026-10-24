#include <Arduino.h>
#include <ESP_Mail_Client.h>
#include <WebServer.h>
#include <WiFi.h>
#include <Wire.h>
#include <math.h>
#include <string.h>

#include "secrets.h"

// Hardware pins
static constexpr uint8_t IR_LED_PIN = 12;
static constexpr uint8_t BUZZER_PIN = 25;
static constexpr uint8_t BEAM_RECEIVER_PIN = 15; // CH1
static constexpr uint8_t RECEIVER_CH2_PIN = 2;
static constexpr uint8_t RECEIVER_CH3_PIN = 4;
// CH4 is RX2/GPIO16 and is intentionally left floating/unused for now.

// Adjust these to match your receiver module.
static constexpr uint32_t IR_CARRIER_HZ = 38000;
static constexpr bool RECEIVER_ACTIVE_HIGH = true;

// Learn this command into CH1 on the receiver module.
static constexpr uint8_t IR_NEC_ADDRESS = 0xA2;
static constexpr uint8_t IR_NEC_COMMAND = 0x10;

// Local access point and web PIN.
static const char *AP_SSID = "DoorSecurity-Fallback";
static const char *CONTROL_PIN = WEB_CONTROL_PIN;
static const char *SMTP_HOST = "smtp.gmail.com";
static constexpr uint16_t SMTP_PORT = 465;

// MPU6050 register addresses.
static constexpr uint8_t MPU6050_ADDR = 0x68;
static constexpr uint8_t MPU_PWR_MGMT_1 = 0x6B;
static constexpr uint8_t MPU_ACCEL_XOUT_H = 0x3B;
static constexpr uint8_t MPU_GYRO_CONFIG = 0x1B;
static constexpr uint8_t MPU_ACCEL_CONFIG = 0x1C;

// ESP32 LEDC setup for the IR carrier.
static constexpr uint8_t IR_PWM_CHANNEL = 0;
static constexpr uint8_t IR_PWM_RESOLUTION_BITS = 8;
static constexpr uint8_t IR_PWM_DUTY_50_PERCENT = 128;

// Detection timing.
static constexpr uint32_t SENSOR_SAMPLE_MS = 20;
static constexpr uint32_t MPU_SAMPLE_MS = 100;
static constexpr uint32_t STATUS_PRINT_MS = 2000;
static constexpr uint32_t WIFI_CONNECT_TIMEOUT_MS = 20000;
static constexpr uint32_t WIFI_RECONNECT_MS = 30000;
static constexpr uint32_t IR_FRAME_PERIOD_MS = 110;
static constexpr uint32_t BEAM_BREAK_CONFIRM_MS = 350;
static constexpr uint32_t TAMPER_CONFIRM_MS = 250;

// Tamper thresholds. Tune after observing normal mounting vibration.
static constexpr float TAMPER_TILT_DEGREES = 30.0f;
static constexpr float TAMPER_GYRO_DPS = 180.0f;
static constexpr float TAMPER_ACCEL_DELTA_G = 0.65f;

enum class DoorMode {
  Open,
  Armed
};

struct Vec3 {
  float x;
  float y;
  float z;
};

struct MpuSample {
  Vec3 accelG;
  Vec3 gyroDps;
  bool ok;
};

struct LogEntry {
  uint32_t uptimeMs;
  char message[72];
};

WebServer server(80);
SMTPSession smtp;

DoorMode doorMode = DoorMode::Open;
bool alarmLatched = false;
bool irLedEnabled = false;
bool beamReceiving = false;
bool receiverCh2 = false;
bool receiverCh3 = false;
bool tamperDetected = false;
bool mpuReady = false;
bool fallbackApStarted = false;
Vec3 baselineAccel = {0.0f, 0.0f, 1.0f};

uint32_t lastSensorSampleMs = 0;
uint32_t lastMpuSampleMs = 0;
uint32_t lastStatusPrintMs = 0;
uint32_t lastWifiReconnectMs = 0;
uint32_t lastIrFrameMs = 0;
uint32_t beamMissingSinceMs = 0;
uint32_t tamperSinceMs = 0;

static constexpr uint8_t LOG_CAPACITY = 16;
LogEntry breachLog[LOG_CAPACITY] = {};
uint8_t breachLogStart = 0;
uint8_t breachLogCount = 0;

bool readActivePin(uint8_t pin) {
  const bool levelHigh = digitalRead(pin) == HIGH;
  return RECEIVER_ACTIVE_HIGH ? levelHigh : !levelHigh;
}

bool isUnsetValue(const char *value) {
  return value == nullptr ||
         value[0] == '\0' ||
         strncmp(value, "YOUR_", 5) == 0 ||
         strstr(value, "your-") != nullptr ||
         strstr(value, "example.com") != nullptr;
}

bool isWifiConfigured() {
  return !isUnsetValue(HOME_WIFI_SSID) && !isUnsetValue(HOME_WIFI_PASSWORD);
}

bool isEmailConfigured() {
  return !isUnsetValue(GMAIL_SENDER_EMAIL) &&
         !isUnsetValue(GMAIL_APP_PASSWORD) &&
         !isUnsetValue(ALERT_RECIPIENT_EMAIL);
}

bool isWifiConnected() {
  return WiFi.status() == WL_CONNECTED;
}

String lanIpText() {
  return isWifiConnected() ? WiFi.localIP().toString() : String("not connected");
}

String apIpText() {
  return fallbackApStarted ? WiFi.softAPIP().toString() : String("off");
}

const char *doorModeText() {
  return doorMode == DoorMode::Armed ? "armed" : "open";
}

void addLog(const char *message) {
  const uint8_t index = (breachLogStart + breachLogCount) % LOG_CAPACITY;
  breachLog[index].uptimeMs = millis();
  snprintf(breachLog[index].message, sizeof(breachLog[index].message), "%s", message);

  if (breachLogCount < LOG_CAPACITY) {
    breachLogCount++;
  } else {
    breachLogStart = (breachLogStart + 1) % LOG_CAPACITY;
  }
}

String uptimeText() {
  const uint32_t seconds = millis() / 1000;
  const uint32_t minutes = seconds / 60;
  const uint32_t hours = minutes / 60;

  String text;
  if (hours > 0) {
    text += hours;
    text += "h ";
  }
  if (minutes > 0) {
    text += minutes % 60;
    text += "m ";
  }
  text += seconds % 60;
  text += "s";
  return text;
}

String makeAlertBody(const char *reason) {
  String body;
  body += "Door Security alert\n\n";
  body += "Event: ";
  body += reason;
  body += "\nDoor status: ";
  body += doorModeText();
  body += "\nReceiver: ";
  body += beamReceiving ? "receiving" : "not receiving signal";
  body += "\nAlarm: ";
  body += alarmLatched ? "on" : "off";
  body += "\nTamper: ";
  body += tamperDetected ? "yes" : "no";
  body += "\nLAN IP: ";
  body += lanIpText();
  body += "\nUptime: ";
  body += uptimeText();
  body += "\n\nRecent log:\n";
  if (breachLogCount == 0) {
    body += "No events\n";
  } else {
    for (uint8_t i = 0; i < breachLogCount; ++i) {
      const uint8_t index = (breachLogStart + i) % LOG_CAPACITY;
      body += "- ";
      body += breachLog[index].message;
      body += " at ";
      body += breachLog[index].uptimeMs / 1000;
      body += "s\n";
    }
  }
  return body;
}

void sendBreachEmail(const char *reason) {
  if (!isWifiConnected()) {
    Serial.println("Email skipped: home WiFi is not connected");
    return;
  }

  if (!isEmailConfigured()) {
    Serial.println("Email skipped: Gmail settings are not configured in include/secrets.h");
    return;
  }

  ESP_Mail_Session session;
  session.server.host_name = SMTP_HOST;
  session.server.port = SMTP_PORT;
  session.login.email = GMAIL_SENDER_EMAIL;
  session.login.password = GMAIL_APP_PASSWORD;
  session.login.user_domain = "";
  session.time.ntp_server = F("pool.ntp.org,time.nist.gov");
  session.time.gmt_offset = 4;
  session.time.day_light_offset = 0;

  SMTP_Message message;
  message.sender.name = F("ESP32 Door Security");
  message.sender.email = GMAIL_SENDER_EMAIL;
  message.subject = F("Door Security Breach");
  message.addRecipient(F("Owner"), ALERT_RECIPIENT_EMAIL);

  const String body = makeAlertBody(reason);
  message.text.content = body.c_str();
  message.text.charSet = F("us-ascii");
  message.text.transfer_encoding = Content_Transfer_Encoding::enc_7bit;

  smtp.debug(1);
  MailClient.networkReconnect(true);

  if (!smtp.connect(&session)) {
    Serial.printf("Email connect failed: %s\n", smtp.errorReason().c_str());
    return;
  }

  if (!MailClient.sendMail(&smtp, &message)) {
    Serial.printf("Email send failed: %s\n", smtp.errorReason().c_str());
  } else {
    Serial.println("Breach email sent");
  }

  smtp.closeSession();
}

void irCarrierOn() {
  ledcWrite(IR_PWM_CHANNEL, IR_PWM_DUTY_50_PERCENT);
}

void irCarrierOff() {
  ledcWrite(IR_PWM_CHANNEL, 0);
}

void setIrTransmitter(bool enabled) {
  irLedEnabled = enabled;
  if (!enabled) {
    irCarrierOff();
  }
}

void irMark(uint16_t durationUs) {
  irCarrierOn();
  delayMicroseconds(durationUs);
}

void irSpace(uint16_t durationUs) {
  irCarrierOff();
  delayMicroseconds(durationUs);
}

void sendNecByte(uint8_t value) {
  for (uint8_t bit = 0; bit < 8; ++bit) {
    irMark(560);
    irSpace((value & 0x01) ? 1690 : 560);
    value >>= 1;
  }
}

void sendLearnableIrCommand() {
  irMark(9000);
  irSpace(4500);
  sendNecByte(IR_NEC_ADDRESS);
  sendNecByte(static_cast<uint8_t>(~IR_NEC_ADDRESS));
  sendNecByte(IR_NEC_COMMAND);
  sendNecByte(static_cast<uint8_t>(~IR_NEC_COMMAND));
  irMark(560);
  irCarrierOff();
}

void updateIrTransmitter() {
  if (!irLedEnabled) {
    return;
  }

  const uint32_t now = millis();
  if (lastIrFrameMs == 0 || now - lastIrFrameMs >= IR_FRAME_PERIOD_MS) {
    lastIrFrameMs = now;
    sendLearnableIrCommand();
  }
}

void setBuzzer(bool enabled) {
  digitalWrite(BUZZER_PIN, enabled ? HIGH : LOW);
}

void applyDoorOutputs() {
  if (doorMode == DoorMode::Armed) {
    setIrTransmitter(true);
    setBuzzer(alarmLatched);
  } else {
    alarmLatched = false;
    tamperDetected = false;
    beamMissingSinceMs = 0;
    tamperSinceMs = 0;
    setIrTransmitter(false);
    setBuzzer(false);
  }
}

String jsonEscape(const char *text) {
  String escaped;
  for (const char *p = text; *p != '\0'; ++p) {
    if (*p == '"' || *p == '\\') {
      escaped += '\\';
    }
    escaped += *p;
  }
  return escaped;
}

void writeMpuRegister(uint8_t reg, uint8_t value) {
  Wire.beginTransmission(MPU6050_ADDR);
  Wire.write(reg);
  Wire.write(value);
  Wire.endTransmission();
}

bool readMpuRaw(int16_t &ax, int16_t &ay, int16_t &az, int16_t &gx, int16_t &gy, int16_t &gz) {
  Wire.beginTransmission(MPU6050_ADDR);
  Wire.write(MPU_ACCEL_XOUT_H);
  if (Wire.endTransmission(false) != 0) {
    return false;
  }

  const uint8_t bytesNeeded = 14;
  if (Wire.requestFrom(MPU6050_ADDR, bytesNeeded) != bytesNeeded) {
    return false;
  }

  ax = (Wire.read() << 8) | Wire.read();
  ay = (Wire.read() << 8) | Wire.read();
  az = (Wire.read() << 8) | Wire.read();
  Wire.read();
  Wire.read();
  gx = (Wire.read() << 8) | Wire.read();
  gy = (Wire.read() << 8) | Wire.read();
  gz = (Wire.read() << 8) | Wire.read();
  return true;
}

MpuSample readMpuSample() {
  int16_t ax;
  int16_t ay;
  int16_t az;
  int16_t gx;
  int16_t gy;
  int16_t gz;

  if (!readMpuRaw(ax, ay, az, gx, gy, gz)) {
    return {{0.0f, 0.0f, 0.0f}, {0.0f, 0.0f, 0.0f}, false};
  }

  return {
      {ax / 16384.0f, ay / 16384.0f, az / 16384.0f},
      {gx / 131.0f, gy / 131.0f, gz / 131.0f},
      true};
}

float vectorMagnitude(const Vec3 &v) {
  return sqrtf((v.x * v.x) + (v.y * v.y) + (v.z * v.z));
}

float dotProduct(const Vec3 &a, const Vec3 &b) {
  return (a.x * b.x) + (a.y * b.y) + (a.z * b.z);
}

float angleBetweenDegrees(const Vec3 &a, const Vec3 &b) {
  const float mag = vectorMagnitude(a) * vectorMagnitude(b);
  if (mag < 0.001f) {
    return 0.0f;
  }

  float cosine = dotProduct(a, b) / mag;
  cosine = constrain(cosine, -1.0f, 1.0f);
  return acosf(cosine) * 180.0f / PI;
}

bool initMpu6050() {
  Wire.begin();
  writeMpuRegister(MPU_PWR_MGMT_1, 0x00);
  delay(100);
  writeMpuRegister(MPU_GYRO_CONFIG, 0x00);  // +/- 250 dps
  writeMpuRegister(MPU_ACCEL_CONFIG, 0x00); // +/- 2 g

  Vec3 sum = {0.0f, 0.0f, 0.0f};
  uint8_t validSamples = 0;
  for (uint8_t i = 0; i < 40; ++i) {
    const MpuSample sample = readMpuSample();
    if (sample.ok) {
      sum.x += sample.accelG.x;
      sum.y += sample.accelG.y;
      sum.z += sample.accelG.z;
      validSamples++;
    }
    delay(10);
  }

  if (validSamples == 0) {
    return false;
  }

  baselineAccel = {
      sum.x / validSamples,
      sum.y / validSamples,
      sum.z / validSamples};
  return true;
}

bool isTamperMotion(const MpuSample &sample) {
  if (!sample.ok) {
    return false;
  }

  const float tilt = angleBetweenDegrees(baselineAccel, sample.accelG);
  const float gyro = vectorMagnitude(sample.gyroDps);
  const float accelDelta = fabsf(vectorMagnitude(sample.accelG) - vectorMagnitude(baselineAccel));

  return tilt >= TAMPER_TILT_DEGREES ||
         gyro >= TAMPER_GYRO_DPS ||
         accelDelta >= TAMPER_ACCEL_DELTA_G;
}

void latchAlarm(const char *reason) {
  if (!alarmLatched) {
    alarmLatched = true;
    addLog(reason);
    Serial.println(reason);
    sendBreachEmail(reason);
  }
}

void updateReceiverInputs() {
  beamReceiving = readActivePin(BEAM_RECEIVER_PIN);
  receiverCh2 = readActivePin(RECEIVER_CH2_PIN);
  receiverCh3 = readActivePin(RECEIVER_CH3_PIN);
}

void updateSecurityState() {
  const uint32_t now = millis();

  if (now - lastSensorSampleMs >= SENSOR_SAMPLE_MS) {
    lastSensorSampleMs = now;
    updateReceiverInputs();

    if (doorMode == DoorMode::Armed) {
      if (!beamReceiving) {
        if (beamMissingSinceMs == 0) {
          beamMissingSinceMs = now;
        } else if (now - beamMissingSinceMs >= BEAM_BREAK_CONFIRM_MS) {
          latchAlarm("Breach: IR beam was broken");
        }
      } else {
        beamMissingSinceMs = 0;
      }
    }
  }

  if (mpuReady && now - lastMpuSampleMs >= MPU_SAMPLE_MS) {
    lastMpuSampleMs = now;
    const bool moving = isTamperMotion(readMpuSample());

    if (doorMode == DoorMode::Armed && moving) {
      if (tamperSinceMs == 0) {
        tamperSinceMs = now;
      } else if (now - tamperSinceMs >= TAMPER_CONFIRM_MS) {
        tamperDetected = true;
        latchAlarm("Breach: module movement/tamper detected");
      }
    } else {
      tamperSinceMs = 0;
      if (doorMode == DoorMode::Open) {
        tamperDetected = false;
      }
    }
  }

  applyDoorOutputs();
}

String logsJson() {
  String output = "[";
  for (uint8_t i = 0; i < breachLogCount; ++i) {
    const uint8_t index = (breachLogStart + i) % LOG_CAPACITY;
    if (i > 0) {
      output += ',';
    }

    output += "{\"uptimeMs\":";
    output += breachLog[index].uptimeMs;
    output += ",\"message\":\"";
    output += jsonEscape(breachLog[index].message);
    output += "\"}";
  }
  output += "]";
  return output;
}

void handleStatus() {
  updateReceiverInputs();

  String json = "{";
  json += "\"doorStatus\":\"";
  json += doorModeText();
  json += "\",\"irLed\":\"";
  json += irLedEnabled ? "on" : "off";
  json += "\",\"receiver\":\"";
  json += beamReceiving ? "receiving" : "not receiving signal";
  json += "\",\"beamReceiving\":";
  json += beamReceiving ? "true" : "false";
  json += ",\"alarm\":";
  json += alarmLatched ? "true" : "false";
  json += ",\"tamper\":";
  json += tamperDetected ? "true" : "false";
  json += ",\"mpu6050\":\"";
  json += mpuReady ? "ready" : "not detected";
  json += "\",\"wifi\":\"";
  json += isWifiConnected() ? "connected" : "not connected";
  json += "\",\"lanIp\":\"";
  json += lanIpText();
  json += "\",\"fallbackApIp\":\"";
  json += apIpText();
  json += "\",\"ch2\":";
  json += receiverCh2 ? "true" : "false";
  json += ",\"ch3\":";
  json += receiverCh3 ? "true" : "false";
  json += ",\"uptimeMs\":";
  json += millis();
  json += ",\"logs\":";
  json += logsJson();
  json += "}";

  server.send(200, "application/json", json);
}

void setDoorMode(DoorMode newMode) {
  if (doorMode == newMode) {
    applyDoorOutputs();
    return;
  }

  doorMode = newMode;
  if (doorMode == DoorMode::Armed) {
    alarmLatched = false;
    tamperDetected = false;
    lastIrFrameMs = 0;
    beamMissingSinceMs = 0;
    tamperSinceMs = 0;
    addLog("System armed");
  } else {
    addLog("System opened");
  }
  applyDoorOutputs();
}

void handleDoorControl() {
  if (!server.hasArg("pin") || server.arg("pin") != CONTROL_PIN) {
    server.send(403, "application/json", "{\"ok\":false,\"error\":\"bad pin\"}");
    return;
  }

  if (!server.hasArg("state")) {
    server.send(400, "application/json", "{\"ok\":false,\"error\":\"missing state\"}");
    return;
  }

  const String state = server.arg("state");
  if (state == "armed") {
    setDoorMode(DoorMode::Armed);
  } else if (state == "open") {
    setDoorMode(DoorMode::Open);
  } else {
    server.send(400, "application/json", "{\"ok\":false,\"error\":\"invalid state\"}");
    return;
  }

  server.send(200, "application/json", "{\"ok\":true}");
}

void handleRoot() {
  static const char page[] PROGMEM = R"HTML(
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Door Security</title>
  <style>
    :root {
      color-scheme: light dark;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #101418;
      color: #eef3f7;
    }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px;
      box-sizing: border-box;
    }
    main {
      width: min(760px, 100%);
    }
    h1 {
      margin: 0 0 18px;
      font-size: clamp(28px, 4vw, 42px);
      letter-spacing: 0;
    }
    .panel {
      border: 1px solid #33404b;
      border-radius: 8px;
      background: #172029;
      padding: 18px;
      margin-bottom: 14px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
    }
    .metric {
      border: 1px solid #2b3742;
      border-radius: 8px;
      padding: 14px;
      background: #111920;
    }
    .label {
      color: #96a5b3;
      font-size: 13px;
      margin-bottom: 8px;
    }
    .value {
      font-size: 22px;
      font-weight: 700;
      overflow-wrap: anywhere;
    }
    .alarm {
      color: #ff6b6b;
    }
    .ok {
      color: #51d88a;
    }
    form {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
    }
    input, button {
      min-height: 42px;
      border-radius: 8px;
      border: 1px solid #3b4a56;
      background: #0f151b;
      color: #eef3f7;
      padding: 0 14px;
      font: inherit;
      box-sizing: border-box;
    }
    input {
      width: 120px;
    }
    button {
      cursor: pointer;
      font-weight: 700;
    }
    button.arm {
      background: #224936;
      border-color: #34724f;
    }
    button.open {
      background: #4c2b2b;
      border-color: #7a4242;
    }
    ul {
      margin: 0;
      padding-left: 18px;
    }
    li {
      margin: 8px 0;
      color: #ccd6df;
    }
    .error {
      color: #ffb86b;
      min-height: 24px;
      margin-top: 10px;
    }
  </style>
</head>
<body>
  <main>
    <h1>Door Security</h1>
    <section class="panel grid">
      <div class="metric"><div class="label">Door status</div><div id="door" class="value">...</div></div>
      <div class="metric"><div class="label">IR LED</div><div id="ir" class="value">...</div></div>
      <div class="metric"><div class="label">Receiver</div><div id="receiver" class="value">...</div></div>
      <div class="metric"><div class="label">Alarm</div><div id="alarm" class="value">...</div></div>
      <div class="metric"><div class="label">MPU6050</div><div id="mpu" class="value">...</div></div>
      <div class="metric"><div class="label">Network</div><div id="network" class="value">...</div></div>
      <div class="metric"><div class="label">Extra channels</div><div id="channels" class="value">...</div></div>
    </section>
    <section class="panel">
      <form id="control">
        <input id="pin" name="pin" type="password" maxlength="4" inputmode="numeric" pattern="[0-9]{4}" placeholder="PIN" required>
        <button class="arm" type="submit" data-state="armed">Arm</button>
        <button class="open" type="submit" data-state="open">Open</button>
      </form>
      <div id="error" class="error"></div>
    </section>
    <section class="panel">
      <div class="label">Breach log</div>
      <ul id="logs"></ul>
    </section>
  </main>
  <script>
    const byId = (id) => document.getElementById(id);
    let selectedState = "armed";

    document.querySelectorAll("button[data-state]").forEach((button) => {
      button.addEventListener("click", () => selectedState = button.dataset.state);
    });

    byId("control").addEventListener("submit", async (event) => {
      event.preventDefault();
      const body = new URLSearchParams({ pin: byId("pin").value, state: selectedState });
      const response = await fetch("/api/door", { method: "POST", body });
      const result = await response.json().catch(() => ({}));
      byId("error").textContent = response.ok ? "" : (result.error || "request failed");
      update();
    });

    function age(ms) {
      const seconds = Math.floor(ms / 1000);
      const minutes = Math.floor(seconds / 60);
      if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
      return `${seconds}s`;
    }

    async function update() {
      const status = await fetch("/api/status").then((r) => r.json());
      byId("door").textContent = status.doorStatus;
      byId("ir").textContent = status.irLed;
      byId("receiver").textContent = status.receiver;
      byId("alarm").textContent = status.alarm ? "on" : "off";
      byId("alarm").className = `value ${status.alarm ? "alarm" : "ok"}`;
      byId("mpu").textContent = status.mpu6050 + (status.tamper ? " / tamper" : "");
      byId("network").textContent = status.wifi === "connected" ? status.lanIp : `AP ${status.fallbackApIp}`;
      byId("channels").textContent = `CH2 ${status.ch2 ? "on" : "off"}, CH3 ${status.ch3 ? "on" : "off"}`;

      const logs = byId("logs");
      logs.innerHTML = "";
      if (!status.logs.length) {
        const item = document.createElement("li");
        item.textContent = "No events";
        logs.appendChild(item);
      } else {
        [...status.logs].reverse().forEach((entry) => {
          const item = document.createElement("li");
          item.textContent = `${age(entry.uptimeMs)}: ${entry.message}`;
          logs.appendChild(item);
        });
      }
    }

    update();
    setInterval(update, 1000);
  </script>
</body>
</html>
)HTML";

  server.send_P(200, "text/html", page);
}

void setupWebServer() {
  server.on("/", HTTP_GET, handleRoot);
  server.on("/api/status", HTTP_GET, handleStatus);
  server.on("/api/door", HTTP_POST, handleDoorControl);
  server.begin();
}

void setupPins() {
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW);

  pinMode(BEAM_RECEIVER_PIN, INPUT);
  pinMode(RECEIVER_CH2_PIN, INPUT);
  pinMode(RECEIVER_CH3_PIN, INPUT);

  ledcSetup(IR_PWM_CHANNEL, IR_CARRIER_HZ, IR_PWM_RESOLUTION_BITS);
  ledcAttachPin(IR_LED_PIN, IR_PWM_CHANNEL);
  setIrTransmitter(false);
}

void startFallbackAccessPoint() {
  if (fallbackApStarted) {
    return;
  }

  WiFi.softAP(AP_SSID);
  fallbackApStarted = true;
  Serial.print("Fallback open WiFi AP started: ");
  Serial.println(AP_SSID);
  Serial.print("Fallback web interface: http://");
  Serial.println(WiFi.softAPIP());
}

bool connectHomeWifi(uint32_t timeoutMs) {
  if (!isWifiConfigured()) {
    Serial.println("Home WiFi is not configured in include/secrets.h");
    return false;
  }

  WiFi.setHostname(DEVICE_HOSTNAME);
  WiFi.begin(HOME_WIFI_SSID, HOME_WIFI_PASSWORD);
  Serial.print("Connecting to home WiFi");

  const uint32_t startedAt = millis();
  while (!isWifiConnected() && millis() - startedAt < timeoutMs) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();

  if (!isWifiConnected()) {
    Serial.println("Home WiFi connection failed");
    return false;
  }

  Serial.print("Connected to home WiFi: ");
  Serial.println(HOME_WIFI_SSID);
  Serial.print("LAN web interface: http://");
  Serial.println(WiFi.localIP());
  return true;
}

void setupWifi() {
  WiFi.mode(WIFI_AP_STA);

  if (!connectHomeWifi(WIFI_CONNECT_TIMEOUT_MS)) {
    startFallbackAccessPoint();
  }
}

void updateWifiConnection() {
  if (!isWifiConfigured() || isWifiConnected()) {
    return;
  }

  const uint32_t now = millis();
  if (now - lastWifiReconnectMs < WIFI_RECONNECT_MS) {
    return;
  }

  lastWifiReconnectMs = now;
  Serial.println("Trying to reconnect to home WiFi...");
  WiFi.disconnect(false);
  WiFi.begin(HOME_WIFI_SSID, HOME_WIFI_PASSWORD);
}

void setup() {
  Serial.begin(115200);
  delay(200);

  setupPins();
  setupWifi();

  Serial.println("Starting MPU6050...");
  mpuReady = initMpu6050();
  Serial.println(mpuReady ? "MPU6050 ready" : "MPU6050 not detected");

  addLog("System booted");
  applyDoorOutputs();
  setupWebServer();
}

void loop() {
  server.handleClient();
  updateWifiConnection();
  updateIrTransmitter();
  updateSecurityState();

  const uint32_t now = millis();
  if (now - lastStatusPrintMs >= STATUS_PRINT_MS) {
    lastStatusPrintMs = now;
    Serial.printf("door=%s ir=%s receiver=%s alarm=%s mpu=%s wifi=%s ip=%s\n",
                  doorModeText(),
                  irLedEnabled ? "on" : "off",
                  beamReceiving ? "receiving" : "not receiving",
                  alarmLatched ? "on" : "off",
                  mpuReady ? "ready" : "missing",
                  isWifiConnected() ? "connected" : "offline",
                  lanIpText().c_str());
  }
}
