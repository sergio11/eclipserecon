import re 
from subdomain_scanner import SubdomainScanner
from vulnerability_scanner import WebVulnerabilityScanner
from website_spider import run_spider
from owasp_security_scanner import OwaspSecurityScanner
from utils.logger import appLogger
from security_analyzer import SecurityAnalyzer

class EclipseRecon:
    """
    EclipseRecon orchestrates a suite of reconnaissance and security analysis tools to gather insights 
    about a target domain or IP address. It performs subdomain discovery, vulnerability scanning,
    website crawling, OWASP testing, and generates security reports.

    Attributes:
        target (str): The target domain or IP address.
        scan_depth (str): The depth of scanning for subdomains (e.g., "normal", "deep").
        ipv6 (bool): Whether to include IPv6 addresses in scans.
        threads (int): Number of concurrent threads for scanning.
        proxies (dict): Proxy configuration for HTTP/HTTPS traffic.
        results (dict): Stores results of all scanning processes.
        is_ip (bool): Whether the target is identified as an IP address.
    """

    def __init__(self, target, scan_depth="normal", ipv6=False, threads=10, proxies=None):
        self.target = target
        self.scan_depth = scan_depth
        self.ipv6 = ipv6
        self.threads = threads
        self.proxies = proxies or {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
        self.results = {}
        self.is_ip = self._is_valid_ip(target)
        if self.is_ip:
            appLogger.info(f"🌐 Target {target} is identified as an IP address.")
        else:
            appLogger.info(f"🌍 Target {target} is identified as a domain.")

    @staticmethod
    def _is_valid_ip(target):
        """
        Determines if the target is a valid IPv4 address.

        Args:
            target (str): The target string to validate.

        Returns:
            bool: True if the target is a valid IPv4 address, False otherwise.
        """
        ip_regex = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        return bool(ip_regex.match(target))

    def _run_subdomain_scanner(self):
        """
        Executes the subdomain scanning process if the target is not an IP address.

        Returns:
            list: A list of discovered subdomains.
        """
        if self.is_ip:
            appLogger.info("⚠️ Skipping subdomain scanning as the target is an IP address.")
            return []
        
        appLogger.info("🔍 Starting subdomain scanning...")
        scanner = SubdomainScanner(
            domain=self.target,
            scan_depth=self.scan_depth,
            ipv6=self.ipv6,
            threads=self.threads
        )
        subdomains = scanner.scan()
        appLogger.info(f"✅ Discovered {len(subdomains)} subdomains.")
        self.results['subdomains'] = subdomains
        return subdomains

    def _run_vulnerability_scanner(self, subdomains=None):
        """
        Executes the web vulnerability scanning process for the target or discovered subdomains.

        Args:
            subdomains (list, optional): List of subdomains to scan. Defaults to None.

        Returns:
            dict: Detected vulnerabilities categorized by target.
        """
        appLogger.info("🔧 Starting vulnerability scanning...")
        vul_scanner = WebVulnerabilityScanner(base_url="http://FUZZ")
        vulnerabilities = {}

        if self.is_ip:
            vul_scanner.base_url = f"http://{self.target}/FUZZ"
            vulnerabilities[self.target] = vul_scanner.start_scan(max_concurrent_requests=10)
            appLogger.info(f"🔒 Vulnerability scan completed for IP {self.target}.")
        else:
            for subdomain, _ in subdomains:
                vul_scanner.base_url = f"http://{subdomain}/FUZZ"
                vulnerabilities[subdomain] = vul_scanner.start_scan(max_concurrent_requests=10)
                appLogger.info(f"🔒 Vulnerability scan completed for subdomain {subdomain}.")
        
        self.results['vulnerabilities'] = vulnerabilities
        return vulnerabilities

    def _run_website_spider(self, subdomains=None):
        """
        Crawls the target or discovered subdomains to generate sitemaps.

        Args:
            subdomains (list, optional): List of subdomains to crawl. Defaults to None.

        Returns:
            list: Generated sitemap file paths.
        """
        appLogger.info("🧭 Starting website crawling...")
        sitemap_files = []

        if self.is_ip:
            run_spider(allowed_domains=[self.target], start_urls=[f"http://{self.target}/"])
            sitemap_files.append(f"{self.target}_sitemap.html")
            appLogger.info(f"🖋️ Sitemap generated for IP {self.target}.")
        else:
            for subdomain, _ in subdomains:
                run_spider(allowed_domains=[subdomain], start_urls=[f"http://{subdomain}/"])
                sitemap_files.append(f"{subdomain}_sitemap.html")
                appLogger.info(f"🖋️ Sitemap generated for subdomain {subdomain}.")
        
        self.results['sitemaps'] = sitemap_files
        return sitemap_files

    def _run_owasp_scanner(self, subdomains=None):
        """
        Performs OWASP security testing on the target or discovered subdomains.

        Args:
            subdomains (list, optional): List of subdomains to test. Defaults to None.

        Returns:
            dict: OWASP scan results categorized by target.
        """
        appLogger.info("🚨 Starting OWASP security analysis...")
        owasp_results = {}

        if self.is_ip:
            target_url = f"http://{self.target}"
            owasp_scanner = OwaspSecurityScanner(target_url=target_url, proxies=self.proxies)
            scan_results = owasp_scanner.perform_full_scan()
            owasp_results[self.target] = scan_results
            appLogger.info(f"🏠 OWASP analysis completed for IP {self.target}.")
        else:
            for subdomain, _ in subdomains:
                target_url = f"http://{subdomain}"
                owasp_scanner = OwaspSecurityScanner(target_url=target_url, proxies=self.proxies)
                scan_results = owasp_scanner.perform_full_scan()
                owasp_results[subdomain] = scan_results
                appLogger.info(f"🏠 OWASP analysis completed for subdomain {subdomain}.")
        
        self.results['owasp'] = owasp_results
        return owasp_results

    def _generate_security_report(self, results):
        """
        Generates a comprehensive security report in PDF and JSON formats.

        Args:
            results (dict): Results of all scanning processes.
        """
        appLogger.info("🔖 Generating security report...")
        try:
            security_analyzer = SecurityAnalyzer(groq_api_key="your_groq_api_key")
            pdf_path = "security_report.pdf"
            json_path = "security_report.json"
            message = security_analyzer.generate_report(
                scan_results=results,
                pdf_path=pdf_path,
                json_path=json_path
            )
            appLogger.info(f"✅ Report generated successfully: {message}")
        except Exception as e:
            appLogger.error(f"❌ Failed to generate security report: {e}")

    def execute(self):
        """
        Executes the full EclipseRecon workflow including subdomain discovery, vulnerability scanning,
        website crawling, OWASP testing, and report generation.
        """
        appLogger.info("⏳ Starting EclipseRecon workflow...")

        subdomains = self._run_subdomain_scanner()
        if not self.is_ip:
            appLogger.info(f"🌐 Found {len(subdomains)} subdomains.")

        vulnerabilities = self._run_vulnerability_scanner(subdomains if not self.is_ip else None)
        appLogger.info(f"🔒 Detected vulnerabilities in {len(vulnerabilities)} targets.")

        sitemaps = self._run_website_spider(subdomains if not self.is_ip else None)
        appLogger.info(f"🖋️ Generated sitemaps for {len(sitemaps)} targets.")

        owasp_results = self._run_owasp_scanner(subdomains if not self.is_ip else None)
        appLogger.info(f"🏠 Completed OWASP analysis on {len(owasp_results)} targets.")

        if self.results:
            self._generate_security_report(results=self.results)

if __name__ == "__main__":
    recon = EclipseRecon(
        target="192.168.11.130:8080",
        scan_depth="test",
        ipv6=False,
        threads=10,
        proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
    )
    recon.execute()