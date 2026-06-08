<div align="center">

# 🔒 SecAudit

**Android security audit tool**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![API](https://img.shields.io/badge/API-24%2B-brightgreen.svg)](https://android-arsenal.com/api?level=24)
[![Language](https://img.shields.io/badge/Language-Kotlin-7F52FF.svg)](https://kotlinlang.org)
[![Platform](https://img.shields.io/badge/Platform-Android-3DDC84.svg)](https://android.com)

Scan your Android device for potential security vulnerabilities and misconfigurations — no root required.

</div>

---

## What it checks

- **Developer options** — USB debugging, ADB over network, mock locations enabled
- **Screen lock** — no PIN/pattern/biometric configured
- **Encryption** — device storage encryption status
- **Unknown sources** — installation from unknown APK sources enabled
- **Outdated OS** — Android security patch level
- **Backup settings** — ADB backup enabled
- **Network** — open WiFi connections, VPN status

## Threat levels

Each finding is rated **LOW / MEDIUM / HIGH** with a plain-language explanation and recommended fix.

## Install

### Build from source

```bash
git clone https://github.com/lpapa1977/SecAudit.git
cd SecAudit
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

## Privacy

SecAudit runs entirely on-device. No data is sent anywhere — no analytics, no network requests.

## No external dependencies

Pure Android SDK + Kotlin stdlib.

## Support

[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-0070ba?style=for-the-badge&logo=paypal&logoColor=white)](https://paypal.me/lpapa1977)

## License

[MIT](LICENSE) © Leonardo Papa
