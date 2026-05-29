<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,40:0f3460,100:16213e&height=220&section=header&text=CipherWatch&fontSize=60&fontColor=00d4ff&fontAlignY=40&desc=Enterprise%20SOC%20Console%20%E2%80%94%20AI-Powered%20Security%20Operations%20Center&descAlignY=62&descSize=17&descColor=8b949e&animation=fadeIn"/>

<br/>

[![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=20&pause=1200&color=00D4FF&center=true&vCenter=true&width=750&lines=🔐+Real-Time+Log+Analysis+%26+Threat+Detection;🤖+AI-Powered+by+LLaMA+3.1+via+OpenRouter;🛡️+SQL+Injection+·+XSS+·+Brute+Force+·+RCE;📊+Live+KPI+Dashboard+with+Chart.js+Visuals)](https://git.io/typing-svg)

<br/>

<a href="https://cipherwatch.42web.io">
  <img src="https://img.shields.io/badge/🔗_Live_Demo-cipherwatch.42web.io-00d4ff?style=for-the-badge"/>
</a>
&nbsp;
<img src="https://img.shields.io/badge/PHP-8.x_Backend-777BB4?style=for-the-badge&logo=php&logoColor=white"/>
&nbsp;
<img src="https://img.shields.io/badge/AI-LLaMA_3.1-00C851?style=for-the-badge"/>
&nbsp;
<img src="https://img.shields.io/badge/Status-Completed-brightgreen?style=for-the-badge"/>

<br/><br/>

<img src="https://github.com/srinivasulabhaskarprabhat-pixel/CipherWatch/blob/main/cipher.png" width="900"/>

</div>

---

## ⚡ Overview

**CipherWatch** is a production-grade, AI-powered SOC (Security Operations Center) dashboard built to analyze, classify, and visualize security logs in real time. It fuses traditional **rule-based heuristic detection** with cutting-edge **LLaMA 3.1 AI analysis** to deliver the intelligence of a professional SOC — with zero databases and zero heavy frameworks.

> *Think less SIEM setup, more instant threat intelligence.*

<table>
<tr>
<td>

**🔍 What it detects**
- SQL Injection
- Cross-Site Scripting (XSS)
- Remote Code Execution (RCE)
- Brute Force Attacks
- DNS Exfiltration & Tunneling
- Port Scanning
- Privilege Escalation
- High-Entropy / Obfuscated Payloads
- Unknown Admin Logins

</td>
<td>

**📊 What it delivers**
- Real-time SOC Dashboard
- AI-generated Incident Reports
- Live KPI Metric Cards
- Attack Distribution Charts
- Severity-Badged Incident Table
- Risk Breakdown Visualization
- Cyberpunk Responsive UI
- Duplicate Incident Prevention

</td>
</tr>
</table>

---

## 🏗️ Architecture

```
 ┌─────────────────────────────────────────────────────────────────┐
 │                         USER INTERFACE                          │
 │              Upload or paste raw security log file              │
 └────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
 ┌─────────────────────────────────────────────────────────────────┐
 │                    Frontend Dashboard                            │
 │                  HTML5 · CSS3 · JavaScript                      │
 └────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
 ┌─────────────────────────────────────────────────────────────────┐
 │                      analyze.php                                 │
 │                    Main Processing Core                          │
 └──────────────┬──────────────────────────┬───────────────────────┘
                │                          │
                ▼                          ▼
 ┌──────────────────────┐      ┌──────────────────────────────────┐
 │   local_scan.php     │      │        OpenRouter API            │
 │  Heuristic Engine    │      │      LLaMA 3.1 AI Analysis       │
 │  O(n) · Zero latency │      │   Deep semantic classification   │
 └──────────────────────┘      └──────────────┬───────────────────┘
                                              │
                                              ▼
                              ┌──────────────────────────────────┐
                              │       incident_parser.php        │
                              │     Structured Report Parsing    │
                              └──────────────┬───────────────────┘
                                             │
                                             ▼
                              ┌──────────────────────────────────┐
                              │      Dashboard Rendering         │
                              │    Charts · KPI Cards · Tables   │
                              └──────────────────────────────────┘
```

---

## 🧠 Key Detection Algorithms

### 🔴 Brute Force Detection
```text
Rule: 3+ failed login attempts from the same IP  →  ALERT
Benefit: Minimizes false positives. Precision over noise.
```

### 🟠 Unknown Admin Login Detection
```text
Rule: Successful admin login from untrusted external IP  →  FLAG
Benefit: Catches insider threats and credential compromise.
```

### 🟡 High-Entropy Payload Detection
```text
Algorithm: Shannon Entropy Analysis
Detects: Base64 injections · Obfuscated malware · Encoded payloads
```

---

## 🛠️ Tech Stack

<div align="center">

| Layer | Technology |
|:---:|:---|
| 🎨 **Frontend** | HTML5 · CSS3 · Vanilla JavaScript · Chart.js |
| ⚙️ **Backend** | PHP 8.x · cURL |
| 🤖 **AI Engine** | OpenRouter API · LLaMA 3.1 8B |
| 🚀 **Deployment** | XAMPP · WAMP · localhost |

</div>

---

## 📂 Project Structure

```bash
CipherWatch/
│
├── 📄 index.html               # SOC Dashboard UI
├── 🎨 soc.css                  # Cyberpunk styling
├── ⚙️  soc.js                   # Frontend logic & Chart.js
│
├── 🔧 analyze.php              # Main processing engine
├── 🤖 ai_request.php           # OpenRouter / LLaMA integration
├── 🔍 local_scan.php           # Heuristic detection rules
├── 📋 incident_parser.php      # AI response structured parser
├── 🛡️  fallback_classifier.php  # Offline fallback detection
├── 🔗 cors.php                 # CORS policy handler
├── 🧰 helpers.php              # Utility functions
│
└── 📖 README.md
```

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/srinivasulabhaskarprabhat-pixel/CipherWatch.git
cd CipherWatch
```

### 2️⃣ Configure Your API Key

Open `ai_request.php` and replace the placeholder:

```php
$API_KEY = "YOUR_OPENROUTER_API_KEY";
```

### 3️⃣ Deploy Locally

```bash
# XAMPP → place in:
htdocs/CipherWatch/

# WAMP → place in:
www/CipherWatch/
```

### 4️⃣ Launch

```
http://localhost/CipherWatch/
```

---

## 📊 Performance Benchmarks

<div align="center">

| Log Volume | Heuristic Scan | AI Analysis | Total Time |
|:---:|:---:|:---:|:---:|
| 50 lines | < 1s | 6–12s | **~10s** |
| 500+ lines | < 1s | 20–35s | **~30s** |

*Local scan complexity: **O(n)** — scales linearly with log size*

</div>

---

## ✅ Test Results

<div align="center">

| Test Case | Result |
|:---|:---:|
| SQL Injection Detection | ✅ PASS |
| XSS Detection | ✅ PASS |
| Brute Force Detection | ✅ PASS |
| Unknown Admin Login | ✅ PASS |
| Remote Code Execution | ✅ PASS |
| Duplicate Incident Prevention | ✅ PASS |
| Mobile Responsiveness | ✅ PASS |
| Markdown Sanitization | ✅ PASS |

</div>

---

## 🛡️ Security Hardening

```
✔  XSS-safe rendering          ✔  Input validation & sanitization
✔  API key protection          ✔  CORS policy enforcement
✔  Request timeout handling    ✔  Markdown injection prevention
```

---

## 🔮 Roadmap

- [ ] 🗄️ Database Integration (MySQL / PostgreSQL)
- [ ] 🔑 JWT Authentication & Role-based Access
- [ ] 📡 Real-time Log Streaming (WebSockets)
- [ ] 🔗 SIEM Platform Integration
- [ ] 📄 PDF Incident Report Export
- [ ] 📧 Email & SMS Alerting
- [ ] 🌍 GeoIP Threat Enrichment
- [ ] 🔄 Multi-log Correlation Engine
- [ ] 🤖 Self-hosted AI Model Support

---

## 👨‍💻 Author

<div align="center">

**Bhaskara Prabhat Srinivasula**
*Cybersecurity Analyst · SOC Engineer · Cloud Security*

<br/>

<a href="https://bhaskar.42web.io"><img src="https://img.shields.io/badge/🌐_Portfolio-bhaskar.42web.io-0A66C2?style=for-the-badge"/></a>
&nbsp;
<a href="https://linkedin.com/in/bhaskara-prabhat-srinivasula-96b7a32b6"><img src="https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=for-the-badge&logo=linkedin&logoColor=white"/></a>
&nbsp;
<a href="https://github.com/srinivasulabhaskarprabhat-pixel"><img src="https://img.shields.io/badge/GitHub-Follow-181717?style=for-the-badge&logo=github&logoColor=white"/></a>

</div>

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:16213e,50:0f3460,100:0d1117&height=130&section=footer&text=Intelligent+Security+Monitoring+Powered+By+AI&fontSize=16&fontColor=00d4ff&fontAlignY=65"/>

<br/>

*If this project helped you, drop a ⭐ — it means the world.*

![Profile Views](https://komarev.com/ghpvc/?username=srinivasulabhaskarprabhat-pixel&style=for-the-badge&color=00d4ff&label=PROJECT+VIEWS)

</div>
