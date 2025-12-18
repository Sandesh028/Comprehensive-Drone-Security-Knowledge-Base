# Drone Security Mitigations Guide

> Best practices and technical implementations for securing UAV systems

---

## Quick Reference: Security Hardening Checklist

### Before Flight
- [ ] Update firmware to latest version
- [ ] Change default WiFi password
- [ ] Disable unnecessary services (Telnet, FTP)
- [ ] Enable secure protocols (WPA3, MAVLink 2.0 signing)
- [ ] Verify GPS signal integrity
- [ ] Check for firmware tampering

### During Operations
- [ ] Monitor for deauthentication attacks
- [ ] Watch for GPS anomalies
- [ ] Use encrypted communication channels
- [ ] Implement geofencing
- [ ] Log all telemetry

### Post-Flight
- [ ] Review flight logs for anomalies
- [ ] Secure stored media
- [ ] Clear sensitive data if needed
- [ ] Report any security incidents

---

## Communication Security

### MAVLink 2.0 with Message Signing

**Configuration (ArduPilot):**

```python
# Enable MAVLink 2.0 signing
from pymavlink import mavutil
import hashlib

# Generate 32-byte signing key
key = hashlib.sha256(b"your-unique-secret-key-here").digest()

# Save to flight controller
conn = mavutil.mavlink_connection('/dev/ttyUSB0', baud=57600)
conn.mav.param_set_send(
    conn.target_system,
    conn.target_component,
    b'BRD_SERIAL0_PROTOCOL',
    2  # MAVLink2
)

# Enable signing
conn.mav.setup_signing(
    conn.target_system,
    conn.target_component,
    1,  # Enable signing
    key,
    0   # Initial link ID
)
```

**PX4 Configuration:**

```bash
# In QGroundControl Parameters
MAV_PROTO_VER = 2
# Generate and set signing key via custom parameter
```

### End-to-End Encryption

**Option 1: MAVSec (ChaCha20)**

```c
// Encrypt MAVLink message payload
void encrypt_mavlink(mavlink_message_t* msg, uint8_t* key) {
    uint8_t nonce[12];
    generate_nonce(nonce);  // Use timestamp + sequence
    
    chacha20_encrypt(
        msg->payload64,
        msg->len,
        key,
        nonce
    );
    
    // Append nonce to message
    memcpy(msg->payload64 + msg->len, nonce, 12);
    msg->len += 12;
}
```

**Option 2: DTLS Tunnel**

```bash
# Using stunnel for DTLS
stunnel /etc/stunnel/drone.conf

# drone.conf
[drone-telemetry]
client = no
accept = 14550
connect = 127.0.0.1:14551
protocol = dtls
cert = /etc/stunnel/drone.pem
```

---

## Network Security

### WiFi Hardening

**hostapd.conf for WPA3:**

```ini
interface=wlan0
driver=nl80211
ssid=DRONE_SECURE
hw_mode=a
channel=36

# WPA3-SAE configuration
wpa=2
wpa_key_mgmt=SAE
wpa_pairwise=CCMP
rsn_pairwise=CCMP
wpa_passphrase=ComplexPassword123!@#

# Management Frame Protection (against deauth attacks)
ieee80211w=2  # Required

# Hide SSID
ignore_broadcast_ssid=1

# MAC filtering (optional)
macaddr_acl=1
accept_mac_file=/etc/hostapd/accept.mac
```

### Disable Unnecessary Services

```bash
#!/bin/bash
# secure_drone.sh - Run on drone's embedded Linux

# Disable Telnet
systemctl stop telnetd
systemctl disable telnetd
update-rc.d -f telnetd remove

# Disable FTP or restrict it
systemctl stop vsftpd
# Or configure secure FTP:
# sed -i 's/anonymous_enable=YES/anonymous_enable=NO/' /etc/vsftpd.conf

# Disable ADB
setprop persist.adb.tcp.port -1
stop adbd

# Close unnecessary ports with iptables
iptables -A INPUT -p tcp --dport 23 -j DROP  # Telnet
iptables -A INPUT -p tcp --dport 21 -j DROP  # FTP
iptables -A INPUT -p tcp --dport 5555 -j DROP  # ADB

# Save iptables rules
iptables-save > /etc/iptables.rules
```

### Network Monitoring

```python
#!/usr/bin/env python3
"""
Drone Network Monitor - Detect attacks on UAV WiFi
"""
from scapy.all import *
import logging

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("DroneMonitor")

DRONE_BSSID = "AA:BB:CC:DD:EE:FF"  # Your drone's MAC
DEAUTH_THRESHOLD = 10

deauth_count = 0

def packet_handler(pkt):
    global deauth_count
    
    if pkt.haslayer(Dot11Deauth):
        deauth_count += 1
        logger.warning(f"Deauth packet detected! Count: {deauth_count}")
        
        if deauth_count > DEAUTH_THRESHOLD:
            logger.critical("DEAUTH ATTACK DETECTED!")
            # Trigger alert, switch frequencies, etc.
            trigger_countermeasures()

def trigger_countermeasures():
    # Switch to backup frequency
    # Alert operator
    # Log incident
    pass

# Start monitoring
sniff(iface="wlan0mon", prn=packet_handler, filter="type mgt subtype deauth")
```

---

## GPS Security

### Multi-Constellation GNSS

```c
// Configure receiver for multiple constellations
#include "ublox_gps.h"

void configure_gps_security() {
    // Enable multiple constellations
    gps_config_t config = {
        .gps = true,
        .glonass = true,
        .galileo = true,
        .beidou = true,
        .sbas = true,  // WAAS/EGNOS for additional verification
    };
    
    ublox_set_config(&config);
    
    // Enable navigation message authentication (if supported)
    ublox_enable_nav_auth(true);
}
```

### GPS Spoofing Detection

```python
#!/usr/bin/env python3
"""
GPS Spoofing Detection using IMU cross-verification
"""
import numpy as np
from dataclasses import dataclass
from typing import Optional

@dataclass
class Position:
    lat: float
    lon: float
    alt: float
    timestamp: float

@dataclass
class Velocity:
    vx: float
    vy: float
    vz: float

class GPSSpoofingDetector:
    def __init__(self, velocity_threshold=2.0, position_threshold=10.0):
        self.vel_threshold = velocity_threshold  # m/s
        self.pos_threshold = position_threshold  # meters
        self.last_gps_pos: Optional[Position] = None
        self.last_imu_pos: Optional[Position] = None
        
    def check_velocity_consistency(self, gps_vel: Velocity, imu_vel: Velocity) -> bool:
        """Compare GPS velocity with IMU-derived velocity"""
        diff = np.sqrt(
            (gps_vel.vx - imu_vel.vx)**2 +
            (gps_vel.vy - imu_vel.vy)**2 +
            (gps_vel.vz - imu_vel.vz)**2
        )
        
        if diff > self.vel_threshold:
            print(f"WARNING: Velocity mismatch detected! Diff: {diff:.2f} m/s")
            return False
        return True
    
    def check_position_jump(self, new_pos: Position, dt: float, max_velocity: float) -> bool:
        """Check for impossible position changes"""
        if self.last_gps_pos is None:
            self.last_gps_pos = new_pos
            return True
        
        # Calculate distance traveled
        distance = self.haversine_distance(
            self.last_gps_pos.lat, self.last_gps_pos.lon,
            new_pos.lat, new_pos.lon
        )
        
        # Check if velocity would exceed max
        implied_velocity = distance / dt
        if implied_velocity > max_velocity:
            print(f"WARNING: Position jump detected! Implied velocity: {implied_velocity:.2f} m/s")
            return False
        
        self.last_gps_pos = new_pos
        return True
    
    def check_cn0_consistency(self, cn0_values: list) -> bool:
        """Check for abnormal signal strength patterns"""
        # Spoofed signals often have unusually consistent or high CN0
        std_dev = np.std(cn0_values)
        mean_cn0 = np.mean(cn0_values)
        
        if std_dev < 1.0 and mean_cn0 > 45:
            print("WARNING: Suspiciously consistent high CN0 values!")
            return False
        return True
    
    @staticmethod
    def haversine_distance(lat1, lon1, lat2, lon2):
        R = 6371000  # Earth radius in meters
        phi1, phi2 = np.radians(lat1), np.radians(lat2)
        dphi = np.radians(lat2 - lat1)
        dlambda = np.radians(lon2 - lon1)
        
        a = np.sin(dphi/2)**2 + np.cos(phi1)*np.cos(phi2)*np.sin(dlambda/2)**2
        return 2*R*np.arcsin(np.sqrt(a))

# Usage in flight controller
detector = GPSSpoofingDetector()

def gps_callback(gps_data):
    # Cross-check with IMU
    imu_velocity = get_imu_velocity()
    gps_velocity = gps_data.velocity
    
    if not detector.check_velocity_consistency(gps_velocity, imu_velocity):
        trigger_gps_spoofing_alert()
        switch_to_visual_navigation()
```

---

## Firmware Security

### Secure Boot Implementation

```c
// Bootloader verification example
#include "crypto.h"

#define PUBLIC_KEY_SIZE 256
#define SIGNATURE_SIZE 256

const uint8_t manufacturer_public_key[PUBLIC_KEY_SIZE] = { /* ... */ };

int verify_firmware(uint32_t firmware_addr, size_t firmware_size) {
    // Read signature from end of firmware image
    uint8_t signature[SIGNATURE_SIZE];
    memcpy(signature, (void*)(firmware_addr + firmware_size - SIGNATURE_SIZE), 
           SIGNATURE_SIZE);
    
    // Calculate SHA-256 hash of firmware
    uint8_t hash[32];
    sha256((uint8_t*)firmware_addr, firmware_size - SIGNATURE_SIZE, hash);
    
    // Verify RSA-PSS signature
    if (!rsa_pss_verify(manufacturer_public_key, hash, signature)) {
        // Signature invalid - refuse to boot
        display_error("FIRMWARE VERIFICATION FAILED");
        enter_recovery_mode();
        return -1;
    }
    
    // Signature valid - continue boot
    return 0;
}

// Rollback protection
int check_firmware_version(uint32_t new_version) {
    uint32_t current_version = read_secure_version_counter();
    
    if (new_version < current_version) {
        // Downgrade attempt - reject
        return -1;
    }
    
    // Update secure counter after successful installation
    write_secure_version_counter(new_version);
    return 0;
}
```

### Firmware Update Security

```python
#!/usr/bin/env python3
"""
Secure Firmware Update Client
"""
import hashlib
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

class SecureFirmwareUpdater:
    def __init__(self, manufacturer_public_key_path):
        with open(manufacturer_public_key_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(f.read())
    
    def verify_firmware(self, firmware_data, signature):
        """Verify firmware signature"""
        try:
            self.public_key.verify(
                signature,
                firmware_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False
    
    def download_and_verify(self, url, expected_hash):
        """Download firmware and verify integrity"""
        response = requests.get(url)
        firmware_data = response.content[:-256]  # Firmware without signature
        signature = response.content[-256:]       # Last 256 bytes is signature
        
        # Verify hash
        actual_hash = hashlib.sha256(firmware_data).hexdigest()
        if actual_hash != expected_hash:
            raise ValueError("Hash mismatch - firmware may be corrupted")
        
        # Verify signature
        if not self.verify_firmware(firmware_data, signature):
            raise ValueError("Signature invalid - firmware may be tampered")
        
        return firmware_data
```

---

## Authentication Hardening

### Secure Pairing Protocol

```python
#!/usr/bin/env python3
"""
Secure Device Pairing using ECDH + HKDF
"""
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os

class SecurePairing:
    def __init__(self):
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
    
    def get_public_key_bytes(self):
        """Get public key for exchange"""
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat
        )
        return self.public_key.public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
    
    def derive_shared_key(self, peer_public_bytes):
        """Derive shared encryption key from peer's public key"""
        peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_secret = self.private_key.exchange(peer_public)
        
        # Derive encryption key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'drone-pairing-v1',
            backend=default_backend()
        ).derive(shared_secret)
        
        return derived_key

# Pairing flow
def pairing_protocol():
    # 1. Drone generates keypair
    drone = SecurePairing()
    drone_pubkey = drone.get_public_key_bytes()
    
    # 2. Controller generates keypair
    controller = SecurePairing()
    controller_pubkey = controller.get_public_key_bytes()
    
    # 3. Exchange public keys (display QR code, NFC, etc.)
    # ...
    
    # 4. Both sides derive same shared key
    drone_key = drone.derive_shared_key(controller_pubkey)
    controller_key = controller.derive_shared_key(drone_pubkey)
    
    assert drone_key == controller_key  # Both have same key!
    
    return drone_key
```

---

## Physical Security

### Debug Port Protection

```c
// Disable JTAG/SWD in production firmware
void disable_debug_interfaces(void) {
    // STM32 example - disable JTAG pins
    __HAL_AFIO_REMAP_SWJ_DISABLE();
    
    // Lock debug access
    FLASH->OPTKEYR = FLASH_OPTKEY1;
    FLASH->OPTKEYR = FLASH_OPTKEY2;
    FLASH->OPTR |= FLASH_OPTR_RDP_Msk;  // Set read protection
    
    // Set JTAG pins as GPIO
    GPIO_InitTypeDef GPIO_InitStruct = {0};
    GPIO_InitStruct.Pin = GPIO_PIN_13|GPIO_PIN_14|GPIO_PIN_15;
    GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);
}
```

### Tamper Detection

```c
// Simple tamper detection using accelerometer
#define TAMPER_THRESHOLD 2.0  // G-force threshold

volatile bool tamper_detected = false;

void accelerometer_interrupt_handler(void) {
    float accel_magnitude = get_accelerometer_magnitude();
    
    if (accel_magnitude > TAMPER_THRESHOLD) {
        tamper_detected = true;
        
        // Secure response
        wipe_encryption_keys();
        log_security_event("TAMPER_DETECTED");
        enter_lockdown_mode();
    }
}
```

---

## Monitoring & Logging

### Security Event Logging

```python
#!/usr/bin/env python3
"""
Drone Security Event Logger
"""
import logging
import hashlib
import json
from datetime import datetime

class SecurityLogger:
    def __init__(self, log_file="security_events.log"):
        self.logger = logging.getLogger("DroneSecurityLog")
        self.logger.setLevel(logging.DEBUG)
        
        handler = logging.FileHandler(log_file)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(handler)
        
        self.event_chain = []  # For integrity verification
    
    def log_event(self, event_type, details, severity="INFO"):
        """Log security event with integrity chain"""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": event_type,
            "details": details,
            "severity": severity,
            "prev_hash": self.event_chain[-1] if self.event_chain else "GENESIS"
        }
        
        # Calculate hash of this event
        event_hash = hashlib.sha256(
            json.dumps(event, sort_keys=True).encode()
        ).hexdigest()
        event["hash"] = event_hash
        self.event_chain.append(event_hash)
        
        # Log based on severity
        log_func = getattr(self.logger, severity.lower(), self.logger.info)
        log_func(json.dumps(event))
        
        return event_hash

# Usage
logger = SecurityLogger()

# Log various security events
logger.log_event("AUTH_FAILURE", {"ip": "192.168.1.100", "attempts": 3}, "WARNING")
logger.log_event("GPS_ANOMALY", {"variance": 15.2, "expected": 2.0}, "WARNING")
logger.log_event("DEAUTH_ATTACK", {"count": 50, "duration_ms": 1000}, "CRITICAL")
```

---

## Quick Commands Reference

```bash
# Network reconnaissance
nmap -sV -p 21,22,23,80,5555,5678 192.168.1.1

# WiFi monitoring
airmon-ng start wlan0
airodump-ng wlan0mon

# MAVLink traffic analysis
mavproxy.py --master=udp:0.0.0.0:14550 --out=tcpout:0.0.0.0:5678

# Firmware extraction
binwalk -e firmware.bin
strings firmware.bin | grep -i "pass\|key\|secret"

# GPS testing (legal testing only!)
# Use gps-sdr-sim with HackRF in isolated environment
```

---

## References

- [ArduPilot Security](https://ardupilot.org/dev/docs/mavlink-signing.html)
- [PX4 Security](https://docs.px4.io/main/en/concept/security.html)
- [OWASP IoT Security](https://owasp.org/www-project-internet-of-things/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
