# OWASP Drone Top 10 Security Risks - Detailed Analysis

## Table of Contents

1. [D01: Insecure Communication](#d01-insecure-communication)
2. [D02: Weak Authentication/Authorization](#d02-weak-authenticationauthorization)
3. [D03: Insecure Firmware/Software](#d03-insecure-firmwaresoftware)
4. [D04: GPS Spoofing](#d04-gps-spoofing)
5. [D05: Insufficient Network Security](#d05-insufficient-network-security)
6. [D06: Inadequate Data Protection](#d06-inadequate-data-protection)
7. [D07: Lack of Secure Update Mechanism](#d07-lack-of-secure-update-mechanism)
8. [D08: Insecure Third-party Components](#d08-insecure-third-party-components)
9. [D09: Physical Security Weaknesses](#d09-physical-security-weaknesses)
10. [D10: Insufficient Logging & Monitoring](#d10-insufficient-logging--monitoring)

---

## D01: Insecure Communication

### Severity: 🔴 CRITICAL

### Description

Transmission of data over unsecured channels, allowing interception or modification of sensitive information including video feeds, telemetry data, and control commands.

### Technical Details

**MAVLink Protocol Vulnerability**

The Micro Air Vehicle Link (MAVLink) protocol is the most widely used communication protocol between drones and Ground Control Stations (GCS). By default, MAVLink:

- Transmits messages **without encryption**
- Does not implement **message authentication**
- Uses predictable **sequence numbers**
- Broadcasts **heartbeat messages** openly

```python
# MAVLink message structure (unencrypted)
class MAVLinkMessage:
    start_byte: 0xFE  # Magic byte
    payload_length: uint8
    sequence: uint8    # Predictable!
    system_id: uint8
    component_id: uint8
    message_id: uint8
    payload: bytes
    checksum: uint16   # CRC only, not cryptographic
```

### Attack Scenarios

1. **Eavesdropping**: Attacker captures telemetry including GPS coordinates, battery status, and video feeds
2. **Command Injection**: Malicious commands sent to disarm motors or change flight path
3. **Replay Attack**: Captured commands replayed to force landing or other actions
4. **Man-in-the-Middle**: Attacker intercepts and modifies commands in real-time

### Real-World Examples

- **ArduPilot/PX4**: Default installations use unencrypted MAVLink
- **DJI Mavic Series**: QuickTransfer mode exposes unencrypted video API
- **Parrot AR.Drone**: UDP-based control without any encryption

### Mitigations

| Mitigation | Implementation | Difficulty |
|------------|----------------|------------|
| MAVLink 2.0 Message Signing | Enable `signing_key` in ArduPilot | Medium |
| End-to-End Encryption | TLS/DTLS tunneling | High |
| ChaCha20 Encryption | MAVSec implementation | Medium |
| Frequency Hopping | Proprietary radio links | High |

### Code Example: Enabling MAVLink Signing

```python
# Enable MAVLink 2.0 signing in ArduPilot
from pymavlink import mavutil

# Generate signing key
import hashlib
key = hashlib.sha256(b"your-secret-key").digest()

# Configure connection with signing
conn = mavutil.mavlink_connection(
    'udp:127.0.0.1:14550',
    source_system=255,
    signing_key=key
)
```

---

## D02: Weak Authentication/Authorization

### Severity: 🔴 CRITICAL

### Description

Inadequate authentication mechanisms allowing unauthorized access to drone controls or sensitive data. Many drones use default credentials, weak pairing, or no authentication at all.

### Technical Details

**Common Authentication Weaknesses:**

1. **Default Credentials**
   - DJI Phantom 3: Default WiFi password `12341234`
   - Many consumer drones: No password required

2. **Weak WiFi Security**
   - Open access points (no encryption)
   - WEP encryption (easily cracked)
   - Predictable SSID patterns

3. **Bluetooth Vulnerabilities**
   - "Just Works" pairing mode
   - No PIN verification
   - Predictable device names

### Attack Scenarios

```
Attacker within WiFi range
         |
         v
+------------------+
| Scan for DRONE_* |
| access points    |
+------------------+
         |
         v
+------------------+
| Connect without  |
| authentication   |
+------------------+
         |
         v
+------------------+
| Access Telnet/   |
| FTP services     |
+------------------+
         |
         v
+------------------+
| Full drone       |
| control achieved |
+------------------+
```

### Real-World Examples

**CVE-2024-52876 (Holy Stone Remote ID)**
- **Attack**: Multiple Bluetooth GATT read operations trigger power off
- **Authentication Required**: None
- **Impact**: Remote denial of service

**CVE-2024-6422 (Consumer UAV Telnet)**
- **Attack**: Connect to open Telnet service
- **Authentication Required**: None
- **Impact**: Full system access, data manipulation

### Mitigations

1. **Change Default Passwords**
   ```bash
   # On drone's embedded Linux (if accessible)
   passwd root
   ```

2. **Enable WPA3 Encryption**
   ```
   # hostapd.conf
   wpa=2
   wpa_key_mgmt=SAE
   wpa_passphrase=your-strong-password
   ```

3. **Implement Device Pairing**
   ```python
   # Secure pairing with key exchange
   from cryptography.hazmat.primitives.asymmetric import x25519
   
   private_key = x25519.X25519PrivateKey.generate()
   public_key = private_key.public_key()
   # Exchange public keys securely
   ```

---

## D03: Insecure Firmware/Software

### Severity: 🟠 HIGH

### Description

Vulnerabilities in drone firmware or software that can be exploited to gain unauthorized access or control. Includes lack of secure boot, unsigned updates, and embedded vulnerabilities.

### Technical Details

**Firmware Security Layers:**

```
+---------------------------+
|     Application Layer     | ← Buffer overflows, logic bugs
+---------------------------+
|       OS Layer           | ← Outdated kernels, misconfigs
+---------------------------+
|    Bootloader Layer      | ← Unsigned updates
+---------------------------+
|     Hardware/TEE         | ← Debug ports, side channels
+---------------------------+
```

### Vulnerability Types

1. **Memory Corruption**
   - CVE-2023-51454: Out-of-bounds write in DJI vtwo_sdk
   - CVE-2023-51455: Array index out of bounds
   - CVE-2023-51456: Stack buffer overflow

2. **Unsigned Firmware**
   - Allows malicious firmware installation
   - Enables persistent backdoors
   - Facilitates downgrade attacks

3. **Debug Interfaces**
   - JTAG/SWD ports left enabled
   - ADB (Android Debug Bridge) accessible
   - Serial console exposed

### Exploitation Example

```bash
# Extract firmware using binwalk
binwalk -e drone_firmware.bin

# Analyze extracted filesystem
find _drone_firmware.bin.extracted -name "*.sh" -exec grep -l "password" {} \;

# Look for hardcoded credentials
strings drone_binary | grep -i "pass\|key\|secret"
```

### Mitigations

**Secure Boot Chain:**

```
ROM Bootloader (immutable)
        |
        v (verify signature)
Second-Stage Bootloader
        |
        v (verify signature)
Linux Kernel
        |
        v (verify signature)
Applications
```

**Implementation:**

```c
// Firmware signature verification
int verify_firmware(uint8_t* firmware, size_t len, uint8_t* signature) {
    // Load manufacturer's public key
    EVP_PKEY* pubkey = load_public_key("manufacturer.pem");
    
    // Verify RSA-PSS signature
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey);
    EVP_DigestVerifyUpdate(ctx, firmware, len);
    
    return EVP_DigestVerifyFinal(ctx, signature, 256) == 1;
}
```

---

## D04: GPS Spoofing

### Severity: 🟠 HIGH

### Description

Manipulation of GPS signals to mislead drone navigation, causing it to deviate from intended flight paths or land in unauthorized locations.

### Technical Details

**GPS Signal Characteristics:**

| Parameter | Value |
|-----------|-------|
| Frequency | L1: 1575.42 MHz, L5: 1176.45 MHz |
| Signal Power | -130 dBm (very weak) |
| Encryption | None (civilian) |
| Authentication | None (civilian) |

**Spoofing Methods:**

1. **Meaconing**: Record and replay legitimate signals with delay
2. **Signal Synthesis**: Generate fake GPS signals using SDR
3. **Seamless Takeover**: Gradually override legitimate signals

### Attack Architecture

```
                    +----------------+
                    |  GPS Satellites |
                    +----------------+
                           |
                    Legitimate signals
                           |
                           v
+----------------+    +---------+    +----------------+
|  SDR Spoofer   |--->| Drone   |<---|  Controller    |
+----------------+    +---------+    +----------------+
  Fake signals            |
  (stronger)              v
                    Wrong position!
```

### Tools & Equipment

- **HackRF One**: SDR for GPS signal generation (~$300)
- **GPS-SDR-SIM**: Open-source GPS simulator
- **BladeRF**: Higher-end SDR platform

### Real-World Impact

| Scenario | Impact |
|----------|--------|
| Delivery Drone | Package delivered to attacker |
| Surveillance | Drone sent to wrong location |
| Agricultural | Crop damage from incorrect spraying |
| Military | Mission failure, asset capture |

### Mitigations

1. **Multi-Constellation GNSS**
   ```c
   // Use GPS + GLONASS + Galileo
   gnss_config.constellations = GPS | GLONASS | GALILEO | BEIDOU;
   ```

2. **IMU Cross-Verification**
   ```python
   def detect_spoofing(gps_velocity, imu_velocity, threshold=2.0):
       diff = abs(gps_velocity - imu_velocity)
       if diff > threshold:
           raise GPSSpoofingDetected(f"Velocity mismatch: {diff} m/s")
   ```

3. **Visual Odometry Backup**
   ```python
   # Compare GPS position with visual position estimate
   visual_position = camera.get_position_estimate()
   gps_position = gps.get_position()
   
   if distance(visual_position, gps_position) > THRESHOLD:
       switch_to_visual_navigation()
   ```

---

## D05: Insufficient Network Security

### Severity: 🟠 HIGH

### Description

Vulnerabilities in drone network services including open WiFi, exposed Telnet/FTP/SSH ports, and weak encryption allowing unauthorized network access.

### Technical Details

**Common Exposed Services:**

| Port | Service | Risk |
|------|---------|------|
| 21 | FTP | Anonymous file access |
| 22 | SSH | Remote shell access |
| 23 | Telnet | Unencrypted root shell |
| 80 | HTTP | Unauthenticated API |
| 554 | RTSP | Video stream capture |
| 5555 | ADB | Android debug shell |
| 5678 | DUML | DJI proprietary protocol |

### Network Scan Example

```bash
# Typical drone network scan
$ nmap -sV -p- 192.168.1.1

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.2
23/tcp   open  telnet      BusyBox telnetd
80/tcp   open  http        lighttpd 1.4.35
554/tcp  open  rtsp        (video stream)
5555/tcp open  adb         Android Debug Bridge

# Connect to telnet - often no password!
$ telnet 192.168.1.1
Connected to 192.168.1.1.
Escape character is '^]'.
/ # id
uid=0(root) gid=0(root)
/ # cat /etc/shadow
root:$1$...:0:0:99999:7:::
```

### WiFi Deauthentication Attack

```bash
# Put interface in monitor mode
airmon-ng start wlan0

# Find drone access point
airodump-ng wlan0mon

# Send deauth packets to disconnect controller
aireplay-ng --deauth 0 -a [DRONE_BSSID] -c [CONTROLLER_MAC] wlan0mon

# Attacker connects and takes control
```

### Mitigations

1. **Disable Unnecessary Services**
   ```bash
   # In /etc/init.d/ or systemd
   systemctl disable telnet
   systemctl disable vsftpd
   ```

2. **Enable 802.11w MFP**
   ```
   # hostapd.conf
   ieee80211w=2  # Required MFP
   ```

3. **Network Segmentation**
   ```
   Control Network (encrypted) ←→ Drone ←→ Telemetry Network (separate)
   ```

---

## D06-D10: Additional Risks

### D06: Inadequate Data Protection
- Encrypt stored media and flight logs
- Implement secure deletion
- Use RAM-only for sensitive keys

### D07: Lack of Secure Update Mechanism
- Sign all firmware updates
- Implement rollback protection
- Verify update integrity before installation

### D08: Insecure Third-party Components
- Maintain Software Bill of Materials (SBOM)
- Regular dependency audits
- Pin specific library versions

### D09: Physical Security Weaknesses
- Disable JTAG/SWD in production
- Implement tamper detection
- Secure USB/debug ports

### D10: Insufficient Logging & Monitoring
- Log all security events
- Implement anomaly detection
- Secure log transmission

---

## References

- [OWASP Drone Security Project](https://owasp.org/www-project-top-10-drone-security-risks/)
- [MAVLink Protocol Documentation](https://mavlink.io/)
- [NIST SP 800-193](https://csrc.nist.gov/pubs/sp/800/193/final)
- [DJI Security Research - Nozomi Networks](https://www.nozominetworks.com/blog/dji-mavic-3-drone-research-part-1-firmware-analysis)
