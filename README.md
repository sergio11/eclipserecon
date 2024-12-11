# EclipseRecon: 🌑 Unveiling the Shadows of the Web 🌐

EclipseRecon is a powerful and stealthy web reconnaissance tool designed to uncover hidden vulnerabilities, subdomains, and intricate site structures that may otherwise remain in the dark. 🕵️‍♂️💻 Using advanced scanning techniques, EclipseRecon enables security professionals to perform thorough assessments of web applications, revealing critical attack surfaces with precision. 🚨🔍 Whether you're conducting penetration testing, vulnerability assessments, or preparing for a cyber defense, EclipseRecon ensures you're always one step ahead in identifying weak spots before malicious actors can exploit them. 🔐💥 With its dark, investigative approach, EclipseRecon helps you stay ahead of potential threats and secure your digital environment.

> ⚠️ **Disclaimer**: This tool is intended for ethical hacking and educational purposes only. Always ensure you have authorization before testing any systems.

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

## 🤝 Contributing
We welcome contributions from the community! Feel free to submit issues, feature requests, or pull requests to help improve EclipseRecon.

## 🛡 Disclaimer
EclipseRecon is intended for **authorized security testing and educational purposes only**. Misuse of this tool for illegal activities is strictly prohibited and may lead to severe penalties.



