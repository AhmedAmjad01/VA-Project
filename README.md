# ASTRA: Integrated Enterprise Vulnerability Management Ecosystem

**Course:** CY451 - Vulnerability Assessment (Fall 2025) [cite: 1]  
**Department:** Cyber Security (CYS) - GIK Institute [cite: 2]  
**Project Status:** Final Release (v1.0)

---

## 📌 Project Overview
**ASTRA** is a comprehensive cyber security simulation designed to replicate a real-world corporate infrastructure. It demonstrates the complete **Vulnerability Management Cycle**, transitioning students from theoretical knowledge to active roles as security analysts, Red Team engineers, and Blue Team defenders[cite: 5, 7].

This project architects a multi-layered environment using **Kali Linux** and **Docker**, performs advanced exploitation (SQLi, XSS, Buffer Overflow), implements active defense (Snort IDS, NGFW), and automates risk reporting via a custom GRC dashboard.

---

## 👨‍🏫 Instructor Information
This project was developed under the guidance of **Engr.Muhammad Ahmad Nawaz**, adhering to the standards of industrial vulnerability assessment and SOC operations.

| **Instructor** | **Contact Details** |
| :--- | :--- |
| **Name** | Engr.Muhammad Ahmad Nawaz |
| **Office** | S01, NAB, GIK Institute |
| **Email** | Engr.ahmad.nawaz@giki.edu.pk |

---

## 🚀 Key Features
### 🔴 Red Team (Offensive Operations)
* **Attack Surface Mapping:** Automated recon using Nmap and Nikto[cite: 15].
* **Web Exploitation:** Proof-of-Concept (PoC) exploits for **SQL Injection** (Authentication Bypass) and **Stored XSS**[cite: 44, 48].
* **Binary Exploitation:** Custom C-backend service exploited via **Buffer Overflow** (Stack-based memory corruption)[cite: 58].

### 🔵 Blue Team (Defensive Operations)
* **Intrusion Detection System (IDS):** **Snort** configured with custom rules to detect attack signatures in real-time[cite: 71].
* **Active Defense (NGFW):** Custom **Next-Generation Firewall** module that automatically bans IPs attempting exploit payloads[cite: 69, 80].

### 📊 Management (GRC & Automation)
* **Risk Heatmap:** Interactive dashboard visualizing node vulnerability status (Critical/High/Medium)[cite: 87].
* **Compliance Mapping:** Findings mapped to **NIST 800-53** and **ISO 27001** standards[cite: 98].

---

## 🛠️ Architecture & Tech Stack
The project utilizes a hybrid architecture of **6-8 nodes** simulated via Docker and Virtualization[cite: 9].

* **Attacker Node:** Kali Linux 2025 (Nmap, Metasploit, Burp Suite).
* **Application Layer:** ASTRA-V (Python/Flask) + Nginx Web Server.
* **Database Layer:** MySQL 5.7 (Legacy) + SQLite (Internal).
* **File Server Layer:** vsftpd (FTP Server).
* **Defense Layer:** Snort IDS + Custom Python Middleware.

---