# 🛡️ CLV - Capture Linux vulnerability
CLV is an educational security auditor built for CTF enthusiasts and Linux system administrators.
The tool helps in identifying common misconfigurations and weak permissions to understand how Linux systems can be hardened.

---

## 🎯 Use Cases
*   CTF Preparation: Speed up the enumeration phase in lab environments.
*   Security Education: Learn how SUID, Cron jobs, and Sudo permissions can lead to system exposure.
*   System Hardening: Audit your own Linux machines to find and fix weak spots.

---

## 🛠️ Features
*   Educational Correlation: Links discovered binaries to [GTFOBins](https://gtfobins.github.io/) to show how default configurations can be misused.
*   Permission Auditor: Scans for world-writable files that need tightening.
*   Environment Analysis: Checks for sensitive leftovers like SSH keys or history files in lab setups.
*   System Integrity: Reports on SUID/SGID bits and Linux Capabilities.

---

## 🚀 How to use in Labs
`bash
git clone [https://github.com/mhmoudjma/CLV.git](https://github.com/mhmoudjma/CLV.git)
cd CLV
chmod +x clv.sh
./clv.sh
