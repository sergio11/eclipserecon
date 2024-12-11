# EclipseRecon: 🌑 Unveiling the Shadows of the Web 🌐

EclipseRecon is a powerful and stealthy web reconnaissance tool designed to uncover hidden vulnerabilities, subdomains, and intricate site structures that may otherwise remain in the dark. 🕵️‍♂️💻 Using advanced scanning techniques, EclipseRecon enables security professionals to perform thorough assessments of web applications, revealing critical attack surfaces with precision. 🚨🔍 Whether you're conducting penetration testing, vulnerability assessments, or preparing for a cyber defense, EclipseRecon ensures you're always one step ahead in identifying weak spots before malicious actors can exploit them. 🔐💥 With its dark, investigative approach, EclipseRecon helps you stay ahead of potential threats and secure your digital environment.

🙏 I would like to express my sincere gratitude to [Santiago Hernández, a leading expert in Cybersecurity and Artificial Intelligence](https://www.udemy.com/user/shramos/). His outstanding course on **Cybersecurity and Ethical Hacking**, available on Udemy, was instrumental in the development of this project. The insights and techniques I gained from his course were invaluable in guiding my approach to cybersecurity practices. Thank you for sharing your knowledge and expertise!

> ⚠️ **Disclaimer**: This tool is intended for ethical hacking and educational purposes only. Always ensure you have authorization before testing any systems.

> ⚠️ All tests and security analysis workflows in **EclipseRecon** were conducted in a controlled environment using deliberately vulnerable websites based on the VPLE (Vulnerable Web Platform for Learning and Exploitation) virtual machine, which is designed specifically for security testing and training purposes. This testing was carried out in a dedicated **lab environment** to ensure ethical use and avoid unauthorized access to any external systems. The results of these tests demonstrate the tool’s effectiveness in identifying vulnerabilities in a controlled, safe, and legal environment.
> 
<p align="center">
  <img src="https://img.shields.io/badge/langchain-1C3C3C?style=for-the-badge&logo=langchain&logoColor=white" />
  <img src="https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white" />
  <img src="https://img.shields.io/badge/Python-FFD43B?style=for-the-badge&logo=python&logoColor=blue" />
</p>

<p align="center">
  <img src="doc/screenshots/picture_1.PNG" />
</p>

## 🎯 Purpose
The primary objective of EclipseRecon is to assist ethical hackers and security analysts in:

- Discovering hidden subdomains.
- Scanning for common vulnerabilities.
- Crawling websites for security insights.
- Performing OWASP-compliant security analysis.
- Generating comprehensive security reports.

By consolidating multiple scanning methodologies, EclipseRecon saves time and enhances accuracy during penetration testing and security assessments.

## 🛠 Features
- **Subdomain Scanning**: Discover subdomains to map the attack surface.
- **Vulnerability Analysis**: Detect common vulnerabilities across web assets.
- **Website Crawling**: Generate sitemaps and analyze website structure.
- **OWASP Testing**: Perform advanced security checks aligned with OWASP standards.
- **Detailed Reporting**: Export results as PDF and JSON reports for further analysis.

## 🌍 Practical Use Cases
EclipseRecon is ideal for:

1. **Penetration Testing**: Quickly enumerate assets and identify weaknesses in a target's infrastructure.
2. **Bug Bounty Hunting**: Identify hidden entry points and vulnerabilities in target systems.
3. **Security Auditing**: Analyze and report on an organization's digital footprint.
4. **Compliance Checks**: Perform OWASP-based analysis to ensure security compliance.

## 📋 Workflow
Here’s a step-by-step breakdown of what EclipseRecon does:

1. **🧭 Initialization**:
   - Validates the target (IP address or domain).
   - Configures proxies and scanning depth.
2. **🔎 Subdomain Scanning**:
   - Discovers subdomains using the `SubdomainScanner` module.
   - Outputs a list of discovered subdomains.
3. **🔧 Vulnerability Scanning**:
   - Scans discovered subdomains or the target for vulnerabilities.
   - Leverages the `WebVulnerabilityScanner` to find potential risks.
4. **🕷️ Website Crawling**:
   - Generates sitemaps by crawling websites or subdomains.
   - Uses the `WebsiteSpider` to map the site structure.
5. **🛡️ OWASP Analysis**:
   - Performs OWASP security checks on targets.
   - Uses the `OwaspSecurityScanner` for detailed testing.
6. **📄 Report Generation**:
   - Compiles results into PDF and JSON reports.
   - Uses the `SecurityAnalyzer` to generate professional-grade reports.

## 🌐 EclipseRecon CLI Options & Usage

EclipseRecon is a powerful tool for reconnaissance and security analysis of websites and IP addresses. Below is a breakdown of the available options for the command-line interface (CLI).

### 📝 Available Options:

### 1. `--target` (Required) 🌍
**Description**: The target domain or IP address that you want to scan. This is a required argument and must be provided.

### 2. `--scan_depth` (Optional) 🔍
**Description**: Set the depth of the subdomain scanning. You can choose from the following options:
- `test`: Basic scan for subdomains.
- `basic`: A deeper scan than `test`, but not as extensive.
- `normal`: A balanced scan (default).
- `deep`: Full-depth scan for all possible subdomains.

**Default**: `normal`

### 3. `--ipv6` (Optional) 🌐
**Description**: Enable scanning of IPv6 addresses (default is IPv4). Use this option if you want to scan for IPv6 addresses.

### 4. `--threads` (Optional) ⚡
**Description**: Define the number of threads to use for scanning. More threads will speed up the process but may consume more resources.

**Default**: `10`

### 5. `--proxies` (Optional) 🔒
**Description**: Set a proxy for the OWASP security scanner to route traffic through a proxy server (e.g., for anonymity or bypassing firewalls).

### 6. `--pdf_report` (Optional) 📄
**Description**: Path to save the PDF security report. If not specified, the report will be saved with the default name `security_report.pdf`.

### 7. `--json_report` (Optional) 📊
**Description**: Path to save the JSON security report. If not specified, the report will be saved with the default name `security_report.json`.

### 8. `--version` (Optional) ℹ️
**Description**: Displays the version of EclipseRecon.

### 📋 Summary of CLI Options

| Option            | Description                                                   | Default               |
|-------------------|---------------------------------------------------------------|-----------------------|
| `--target`        | The target domain or IP address to scan.                      | Required              |
| `--scan_depth`    | Subdomain scan depth: `test`, `basic`, `normal`, `deep`.       | `normal`              |
| `--ipv6`          | Enable IPv6 scanning (optional).                              | Disabled              |
| `--threads`       | Number of threads for scanning (default is 10).               | `10`                  |
| `--proxies`       | Proxy settings for the OWASP scanner.                         | None                  |
| `--pdf_report`    | Path to save the PDF security report.                         | `security_report.pdf` |
| `--json_report`   | Path to save the JSON security report.                        | `security_report.json`|
| `--version`       | Displays the version of EclipseRecon.                         | None                  |


Now you can use these options to scan websites or IP addresses for vulnerabilities, subdomains, OWASP security issues, and more. 🚀

## ⚠️ Disclaimer

**EclipseRecon is designed as a security testing and reconnaissance tool** for ethical hacking and vulnerability analysis. Its main purpose is to automate the process of discovering subdomains, identifying vulnerabilities, performing OWASP security checks, and generating detailed reports based on the gathered insights. **EclipseRecon is intended for ethical and authorized use only**. Unauthorized use may result in severe legal consequences. Always ensure that you have proper authorization and are conducting your activities in a controlled, legal, and ethical environment, such as a lab setup or with explicit permission to use this tool on any system.

All tests and security analysis workflows in **EclipseRecon** were conducted in a controlled environment using deliberately vulnerable websites based on the VPLE (Vulnerable Web Platform for Learning and Exploitation) virtual machine, which is designed specifically for security testing and training purposes. This testing was carried out in a dedicated **lab environment** to ensure ethical use and avoid unauthorized access to any external systems. The results of these tests demonstrate the tool’s effectiveness in identifying vulnerabilities in a controlled, safe, and legal environment.

## 🛡️ Legal

The author of EclipseRecon is not responsible for any misuse or damage caused by this tool. Use responsibly and comply with all local laws.

## Acknowledgements 🙏

🙏 I would like to express my sincere gratitude to [Santiago Hernández, a leading expert in Cybersecurity and Artificial Intelligence](https://www.udemy.com/user/shramos/). His outstanding course on **Cybersecurity and Ethical Hacking**, available on Udemy, was instrumental in the development of this project. The insights and techniques I gained from his course were invaluable in guiding my approach to cybersecurity practices. Thank you for sharing your knowledge and expertise!

## 🤝 **Contributing**
Contributions to EclipseRecon are highly encouraged! If you're interested in adding new features, resolving bugs, or enhancing the project's functionality, please feel free to submit pull requests.

## Get in Touch 📬

EclipseRecon is developed and maintained by **Sergio Sánchez Sánchez** (Dream Software). Special thanks to the open-source community and the contributors who have made this project possible. If you have any questions, feedback, or suggestions, feel free to reach out at  [dreamsoftware92@gmail.com](mailto:dreamsoftware92@gmail.com).

## License ⚖️

This project is licensed under the MIT License, an open-source software license that allows developers to freely use, copy, modify, and distribute the software. 🛠️ This includes use in both personal and commercial projects, with the only requirement being that the original copyright notice is retained. 📄

Please note the following limitations:

- The software is provided "as is", without any warranties, express or implied. 🚫🛡️
- If you distribute the software, whether in original or modified form, you must include the original copyright notice and license. 📑
- The license allows for commercial use, but you cannot claim ownership over the software itself. 🏷️

The goal of this license is to maximize freedom for developers while maintaining recognition for the original creators.

```
MIT License

Copyright (c) 2024 Dream software - Sergio Sánchez 

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```





