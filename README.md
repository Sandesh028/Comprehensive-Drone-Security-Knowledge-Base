# 🛡️ Drone Security Knowledge Base (DroneSecKB)

<p align="center">
  <img src="https://img.shields.io/badge/OWASP-Drone%20Top%2010-00f5d4?style=for-the-badge" alt="OWASP Drone Top 10">
  <img src="https://img.shields.io/badge/CVEs-7%2B%20Documented-ff4757?style=for-the-badge" alt="CVEs">
  <img src="https://img.shields.io/badge/Attack%20Vectors-15%2B-ffa502?style=for-the-badge" alt="Attack Vectors">
  <img src="https://img.shields.io/badge/License-MIT-a855f7?style=for-the-badge" alt="License">
</p>

<p align="center">
  <strong>A comprehensive cybersecurity knowledge base for drone/UAV vulnerabilities, attack vectors, and defense strategies.</strong>
</p>

---

## 📖 Overview

The **Drone Security Knowledge Base** addresses the critical gap in consolidated UAV cybersecurity information. With over 70% of practitioners lacking awareness of UAV cyber risks ([Frontiers, 2025](https://www.frontiersin.org/journals/communications-and-networks/articles/10.3389/frcmn.2025.1661928/full)), this project provides a centralized, accessible resource for:

- **Security Researchers** investigating drone vulnerabilities
- **Penetration Testers** assessing UAV systems
- **Drone Manufacturers** improving product security
- **Regulatory Bodies** developing security standards
- **Hobbyists & Operators** understanding risks

## 🎯 Features

### OWASP Drone Top 10 Security Risks

Based on the official [OWASP Drone Security Project](https://owasp.org/www-project-top-10-drone-security-risks/), covering:

| # | Risk | Severity |
|---|------|----------|
| 1 | Insecure Communication | 🔴 Critical |
| 2 | Weak Authentication/Authorization | 🔴 Critical |
| 3 | Insecure Firmware/Software | 🟠 High |
| 4 | GPS Spoofing | 🟠 High |
| 5 | Insufficient Network Security | 🟠 High |
| 6 | Inadequate Data Protection | 🟡 Medium |
| 7 | Lack of Secure Update Mechanism | 🟡 Medium |
| 8 | Insecure Third-party Components | 🟡 Medium |
| 9 | Physical Security Weaknesses | 🟡 Medium |
| 10 | Insufficient Logging & Monitoring | 🟢 Low |

### CVE Database

Documented vulnerabilities with technical details:

| CVE ID | Product | CVSS | Status |
|--------|---------|------|--------|
| CVE-2024-52876 | Holy Stone Remote ID Module | 7.5 | Patched |
| CVE-2024-6422 | Consumer UAV (Multiple) | 9.8 | Vendor Notified |
| CVE-2023-6951 | DJI Mavic 3 Series | 6.6 | Patched |
| CVE-2023-51454-56 | DJI Mavic 3 vtwo_sdk | 6.8 | Patched |

### Attack Vector Categories

- **Communication Attacks**: WiFi Deauth, MAVLink Injection, Replay, MITM
- **GPS/Navigation Attacks**: GPS Spoofing, Jamming, IMU Manipulation
- **Network Attacks**: Telnet Access, FTP Exploitation, DoS
- **Firmware Attacks**: Extraction, Downgrade, Code Injection

### Tools & Resources

Curated collection of:
- Offensive security tools (DroneSploit, Damn Vulnerable Drone)
- Analysis frameworks (DJI Firmware Tools, pymavlink)
- Standards (OWASP, NIST SP 800-193, ETSI EN 303 645)

## 🚀 Quick Start

### Option 1: View Online

Simply open `index.html` in any modern web browser.

### Option 2: Local Server

```bash
# Clone the repository
git clone https://github.com/yourusername/drone-security-kb.git
cd drone-security-kb

# Serve with Python
python3 -m http.server 8080

# Or use Node.js
npx serve .
```

Then navigate to `http://localhost:8080`

### Option 3: GitHub Pages

1. Fork this repository
2. Go to Settings → Pages
3. Select "Deploy from a branch" → main
4. Access at `https://yourusername.github.io/drone-security-kb`

## 📚 Knowledge Base Structure

```
drone-security-kb/
├── index.html          # Main application (single-page)
├── README.md           # This file
├── LICENSE             # MIT License
└── docs/
    ├── OWASP_TOP_10.md # Detailed risk descriptions
    ├── CVE_DATABASE.md # Full CVE documentation
    ├── ATTACK_VECTORS.md # Attack methodologies
    └── MITIGATIONS.md  # Defense strategies
```

## 🔬 Key Vulnerabilities Highlighted

### 1. MAVLink Protocol Insecurity

The MAVLink protocol, used by ArduPilot, PX4, and many commercial drones, transmits **unencrypted messages** by default.

```python
# Example: Sniffing MAVLink traffic
from pymavlink import mavutil

# Connect to drone
master = mavutil.mavlink_connection('udp:0.0.0.0:14550')

while True:
    msg = master.recv_match(blocking=True)
    print(f"[{msg.get_type()}] {msg.to_dict()}")
```

**Mitigation**: Implement MAVLink 2.0 with message signing and ChaCha20 encryption.

### 2. Open Network Services

Many consumer drones expose dangerous services:

```bash
# Common drone network scan results
$ nmap -sV 192.168.1.1

PORT     STATE SERVICE
21/tcp   open  ftp         # Anonymous access!
23/tcp   open  telnet      # Root shell!
80/tcp   open  http        # Unauthenticated API
5555/tcp open  adb         # Android Debug Bridge
```

**Mitigation**: Disable unnecessary services, enforce authentication.

### 3. GPS Spoofing Vulnerability

Civil GPS signals are unencrypted, making drones vulnerable to position manipulation.

```
Attacker → [Fake GPS Signal] → Drone GPS Receiver
                                    ↓
                              [False Position]
                                    ↓
                              [Navigation Error]
```

**Mitigation**: Multi-constellation GNSS, IMU fusion, visual positioning backup.

## 🛠️ Security Testing Checklist

Use this checklist when assessing drone security:

- [ ] **Network Reconnaissance**
  - [ ] Identify WiFi access point
  - [ ] Scan for open ports (21, 22, 23, 80, 5555)
  - [ ] Check for default credentials
  
- [ ] **Communication Security**
  - [ ] Test for unencrypted traffic
  - [ ] Attempt replay attacks
  - [ ] Check MAVLink message signing

- [ ] **Authentication Testing**
  - [ ] Try default passwords
  - [ ] Test Bluetooth pairing security
  - [ ] Attempt session hijacking

- [ ] **Firmware Analysis**
  - [ ] Extract and analyze firmware
  - [ ] Check for signed updates
  - [ ] Look for hardcoded credentials

- [ ] **Physical Security**
  - [ ] Check for debug ports (JTAG/SWD)
  - [ ] Test tamper detection
  - [ ] Analyze storage encryption

## 📊 Risk Assessment Matrix

| Likelihood ↓ / Impact → | Low | Medium | High | Critical |
|------------------------|-----|--------|------|----------|
| **Very High** | 🟡 | 🟠 | 🔴 | 🔴 |
| **High** | 🟢 | 🟡 | 🟠 | 🔴 |
| **Medium** | 🟢 | 🟡 | 🟠 | 🟠 |
| **Low** | 🟢 | 🟢 | 🟡 | 🟡 |

## 🔗 External Resources

### Official Standards
- [OWASP Drone Top 10](https://owasp.org/www-project-top-10-drone-security-risks/)
- [OWASP Drone Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Drone_Security_Cheat_Sheet.html)
- [NIST SP 800-193 Platform Firmware Resiliency](https://csrc.nist.gov/pubs/sp/800/193/final)
- [ETSI EN 303 645 Consumer IoT Security](https://www.etsi.org/technologies/consumer-iot-security)

### Research & Publications
- [D3S: Drone Security Scoring System (MDPI 2024)](https://www.mdpi.com/2078-2489/15/12/811)
- [DJI Mavic 3 Research - Nozomi Networks](https://www.nozominetworks.com/blog/dji-mavic-3-drone-research-part-1-firmware-analysis)
- [MAVSec: Securing MAVLink Protocol](https://arxiv.org/abs/1905.00265)
- [GPS Spoofing Survey - PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC8114815/)

### Security Tools
- [DroneSploit](https://github.com/dhondta/dronesploit) - Metasploit-like drone exploitation framework
- [Damn Vulnerable Drone](https://github.com/nicholasaleks/Damn-Vulnerable-Drone) - Practice environment
- [DJI Firmware Tools](https://github.com/o-gs/dji-firmware-tools) - Firmware analysis utilities

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-cve`)
3. Commit your changes (`git commit -am 'Add CVE-2024-XXXXX'`)
4. Push to the branch (`git push origin feature/new-cve`)
5. Open a Pull Request

### Adding New CVEs

When adding new CVEs, please include:
- CVE ID and NVD link
- Affected product/firmware version
- CVSS score and severity
- Technical description
- Proof of concept (if public)
- Mitigation steps
- References

## ⚠️ Disclaimer

This knowledge base is for **educational and defensive security research purposes only**.

- **Do NOT** use this information to attack systems without authorization
- **Always** obtain proper permission before security testing
- **Respect** responsible disclosure practices
- **Comply** with all applicable laws and regulations

Unauthorized access to computer systems is illegal and unethical.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OWASP Foundation](https://owasp.org/) for the Drone Security Project
- Security researchers who responsibly disclose drone vulnerabilities
- The open-source drone security community

---

<p align="center">
  <strong>Built for the UAV Security Research Community</strong><br>
  ⭐ Star this repo if you find it useful!
</p>
