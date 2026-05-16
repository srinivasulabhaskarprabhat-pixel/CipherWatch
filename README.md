<p align="center">
<img src="https://github.com/your-username/Enterprise-SOC-Console/blob/main/cipherwatch.png" width="1000">
</p>

<h1 align="center">🛡 Enterprise SOC Console</h1>

<h3 align="center">
AI-Powered Security Operations Center (SOC) Dashboard
</h3>

<p align="center">
<img src="https://img.shields.io/badge/PHP-Backend-blue">
<img src="https://img.shields.io/badge/AI-LLaMA%203.1-green">
<img src="https://img.shields.io/badge/Cybersecurity-SOC-red">
<img src="https://img.shields.io/badge/Chart.js-Visualization-orange">
<img src="https://img.shields.io/badge/Project-Completed-brightgreen">
</p>

---

## 🚀 Overview

Enterprise SOC Console is an AI-powered cybersecurity dashboard designed to analyze, classify, and visualize security logs in real time.

The platform combines traditional rule-based threat detection with modern AI analysis using **LLaMA 3.1 via OpenRouter API**.

The system provides:

- Real-time log analysis  
- AI-powered threat classification  
- Brute-force attack detection  
- Unknown admin login detection  
- Interactive SOC dashboard  
- Live KPI visualization  
- Threat analytics using Chart.js  

Built using **PHP, JavaScript, HTML/CSS, and Chart.js**, the platform delivers a lightweight SOC environment without requiring databases or heavy frameworks.

---

## ✨ Features

✔ AI-Powered Security Log Analysis  
✔ Real-time SOC Dashboard  
✔ Brute Force Attack Detection  
✔ Unknown Admin Login Detection  
✔ SQL Injection Detection  
✔ Cross-Site Scripting (XSS) Detection  
✔ Remote Code Execution (RCE) Detection  
✔ DNS Tunneling Detection  
✔ Port Scan Detection  
✔ High-Entropy Payload Detection  
✔ Interactive KPI Cards  
✔ Cyberpunk Responsive UI  
✔ Chart.js Visualizations  
✔ Dual-stage AI Detection Pipeline  
✔ Duplicate Incident Prevention  

---

## 🏗 Architecture

```text
User Uploads Log File
          |
          v
+----------------------+
| Frontend Dashboard   |
| HTML CSS JavaScript  |
+----------------------+
          |
          v
+----------------------+
| analyze.php          |
| Main Processing      |
+----------------------+
          |
          v
+----------------------+
| local_scan.php       |
| Heuristic Detection  |
+----------------------+
          |
          v
+----------------------+
| OpenRouter API       |
| LLaMA 3.1 Analysis   |
+----------------------+
          |
          v
+----------------------+
| incident_parser.php  |
| Structured Parsing   |
+----------------------+
          |
          v
+----------------------+
| Dashboard Rendering  |
| Charts + KPI Cards   |
+----------------------+
```

---

## 🛠 Tech Stack

### Frontend
- HTML5
- CSS3
- Vanilla JavaScript
- Chart.js

### Backend
- PHP 8.x
- cURL

### AI & APIs
- OpenRouter API
- LLaMA 3.1 8B

### Deployment
- XAMPP
- WAMP

---

## 📂 Project Structure

```bash
Enterprise-SOC-Console/
│
├── index.html
├── soc.css
├── soc.js
├── analyze.php
├── cors.php
├── helpers.php
├── fallback_classifier.php
├── local_scan.php
├── ai_request.php
├── incident_parser.php
│
└── README.md
```

---

## ⚙️ How It Works

### Step 1
User uploads or pastes logs into the dashboard.

### Step 2
Logs are scanned locally using heuristic detection rules.

### Step 3
Suspicious patterns are sent to LLaMA 3.1 through OpenRouter API.

### Step 4
AI classifies attacks and generates incident reports.

### Step 5
Parsed incidents are visualized in the SOC dashboard.

---

## 🔍 Detection Capabilities

- SQL Injection
- Cross-Site Scripting (XSS)
- Remote Code Execution
- Brute Force Attacks
- DNS Exfiltration
- Port Scanning
- Privilege Escalation
- Suspicious Process Execution
- Unknown/Anomalous Activity

---

## 🧠 Key Algorithms

### 🔹 Brute Force Detection
Triggers only when:

```text
3 or more failed login attempts from same IP
```

This minimizes false positives.

---

### 🔹 Unknown Admin Login Detection
Flags successful administrator logins from untrusted external IP ranges.

---

### 🔹 High Entropy Detection
Uses Shannon Entropy analysis to detect:

- Encoded payloads
- Obfuscated malware
- Base64 injections

---

## 🔧 Installation

Clone repository:

```bash
git clone https://github.com/your-username/Enterprise-SOC-Console.git
cd Enterprise-SOC-Console
```

---

## Configure OpenRouter API Key

Update:

```php
$API_KEY = "YOUR_API_KEY";
```

inside:

```bash
ai_request.php
```

---

## ▶ Run Project

Move project into:

### XAMPP
```bash
htdocs/
```

### WAMP
```bash
www/
```

Then open:

```bash
http://localhost/Enterprise-SOC-Console/
```

---

## 📊 Dashboard Components

Features include:

- KPI Metric Cards
- Incident Table
- Severity Badges
- Attack Distribution Chart
- Risk Breakdown Chart
- Analysis Timer
- Responsive Layout

---

## 🛡 Security Features

✔ XSS-safe rendering  
✔ API key protection  
✔ Input validation  
✔ Request timeout handling  
✔ Markdown sanitization  
✔ CORS handling  

---

## 📈 Performance

| Log Size | Average Analysis Time |
|---|---|
| 50 lines | 6–12 seconds |
| 500+ lines | 20–35 seconds |

Local scanning operates in:

```text
O(n)
```

time complexity.

---

## ✅ Test Cases

| Test Case | Status |
|---|---|
| SQL Injection Detection | ✅ PASS |
| XSS Detection | ✅ PASS |
| Brute Force Detection | ✅ PASS |
| Unknown Admin Login | ✅ PASS |
| RCE Detection | ✅ PASS |
| Duplicate Prevention | ✅ PASS |
| Mobile Responsiveness | ✅ PASS |
| Markdown Parsing | ✅ PASS |

---

## 🔮 Future Enhancements

- Database Integration  
- JWT Authentication  
- Real-time Log Streaming  
- SIEM Integration  
- PDF Report Export  
- Email/SMS Alerts  
- GeoIP Enrichment  
- Multi-log Correlation  
- Self-hosted AI Models  

---

## 📚 Learning Outcomes

This project helped in gaining experience with:

- Cybersecurity Log Analysis
- AI-powered Threat Detection
- PHP Backend Development
- Security Operations Center Design
- API Integration
- Threat Visualization
- Detection Engineering
- Web Security

---

## 👨‍💻 Author

**Bhaskara Prabhat Srinivasula**

🌐 Portfolio:  
https://bhaskar.42web.io/

GitHub:  
https://github.com/BhaskarPrabhat

LinkedIn:  
https://www.linkedin.com/in/bhaskara-prabhat-srinivasula-96b7a32b6

---

## ⭐ Support

If you like this project:

Give it a ⭐ on GitHub

---

<h2 align="center">
🛡 Intelligent Security Monitoring Powered By AI
</h2>
