# Door Security System

ESP32 door-monitor prototype with a coded infrared beam, MPU6050 tamper sensing, buzzer, local web panel, and optional SMTP breach notifications.

## Detection

- NEC-coded infrared transmission at 38 kHz, with receiver CH1 as the beam input.
- Beam-break confirmation: 350 ms; tamper confirmation: 250 ms.
- MPU6050 baseline-relative tilt, angular-speed, and acceleration-change checks.
- Open / Armed modes, latched alarm, and a 16-entry in-memory breach log.

## Hardware

| Function | GPIO |
| --- | --- |
| IR transmitter | 12 |
| Buzzer | 25 |
| Receiver CH1 / beam | 15 |
| Receiver CH2 / CH3 | 2 / 4 |

MPU6050 uses I2C. CH4 is intentionally unused. Confirm receiver active polarity and mounting thresholds against your own module.

## Local configuration and build

1. Copy `include/secrets.example.h` to `include/secrets.h`.
2. Supply your own Wi-Fi values, optional Gmail app credentials and recipient, and a private `WEB_CONTROL_PIN`. The real configuration file is ignored by Git and was not copied from the lab installation.
3. Run `pio run`. Flash only when ready using `pio run -t upload`.

The controller attempts home Wi-Fi and can provide a fallback access point. The PIN-protected local HTTP control is an experimental interface, not a hardened remote-access service. Email requires configured credentials and network access. Hardware behavior remains dependent on the actual wiring and calibration.
