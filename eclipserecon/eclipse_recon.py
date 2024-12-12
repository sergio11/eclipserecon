import re 
from eclipserecon.core.subdomain_scanner import SubdomainScanner
from eclipserecon.core.vulnerability_scanner import WebVulnerabilityScanner
from eclipserecon.core.website_spider import run_spider
from eclipserecon.core.owasp_security_scanner import OwaspSecurityScanner
from eclipserecon.utils.logger import appLogger
from eclipserecon.core.security_analyzer import SecurityAnalyzer
from eclipserecon import __version__

class EclipseRecon:
    """
    EclipseRecon is a comprehensive reconnaissance and security analysis tool designed to gather insights 
    about a target domain or IP address. It performs a series of security tests and generates detailed reports.

    The tool integrates the following key features:
        - Subdomain discovery using the SubdomainScanner.
        - Vulnerability scanning with WebVulnerabilityScanner.
        - Website crawling and sitemap generation.
        - OWASP testing using OwaspSecurityScanner.
        - Security report generation in PDF and JSON formats.

    Attributes:
        target (str): The target domain or IP address to analyze.
        subdomainScanner (SubdomainScanner): An instance of SubdomainScanner for discovering subdomains.
        vul_scanner (WebVulnerabilityScanner): An instance of WebVulnerabilityScanner for identifying vulnerabilities.
        owasp_scanner (OwaspSecurityScanner): An instance of OwaspSecurityScanner for performing OWASP security checks.
        security_analyzer (SecurityAnalyzer): An instance for analyzing overall security.
        is_ip (bool): A boolean indicating whether the target is an IP address or domain.
    
    Methods:
        __init__(self, target, scan_depth="normal", ipv6=False, threads=10, proxies=None):
            Initializes the EclipseRecon class with the target and configurations for scanning and analysis.
        
        execute(self, pdf_path="security_report.pdf", json_path="security_report.json"):
            Runs the full reconnaissance and security analysis workflow, including subdomain discovery, vulnerability scanning,
            website crawling, OWASP testing, and report generation in both PDF and JSON formats.
    """

    def __init__(self, target, scan_depth="normal", ipv6=False, threads=10, proxies=None):
        """
        Initializes the EclipseRecon class with the target domain or IP address and sets up the necessary tools 
        for the reconnaissance process.

        Args:
            target (str): The target domain or IP address for the reconnaissance.
            scan_depth (str): The level of subdomain scan to perform ('test', 'basic', 'normal', or 'deep'). Defaults to 'normal'.
            ipv6 (bool): If True, the scan will resolve AAAA (IPv6) records instead of A (IPv4) records. Defaults to False.
            threads (int): The number of threads to use for parallel scanning. Defaults to 10.
            proxies (dict, optional): A dictionary of proxy settings to use for OWASP scanner. Defaults to None.
        """
        self._print_banner()
        self.target = target
        self.subdomainScanner = SubdomainScanner(
            domain=target,
            scan_depth=scan_depth,
            ipv6=ipv6,
            threads=threads
        )
        self.vul_scanner = WebVulnerabilityScanner(
            base_url="http://FUZZ",
            scan_depth=scan_depth
        )
        self.owasp_scanner = OwaspSecurityScanner(proxies=proxies)
        self.security_analyzer = SecurityAnalyzer()
        self.is_ip = self._is_valid_ip(target)

        if self.is_ip:
            appLogger.info(f"🌐 Target {target} is identified as an IP address.")
        else:
            appLogger.info(f"🌍 Target {target} is identified as a domain.")

    def execute(self, pdf_path="security_report.pdf", json_path="security_report.json"):
        """
        Executes the complete EclipseRecon workflow by performing subdomain discovery, vulnerability scanning, 
        website crawling, OWASP security testing, and generating a security report.

        The process is divided into several steps:
            1. **Subdomain discovery**: Scans for subdomains related to the target.
            2. **Vulnerability scanning**: Identifies potential security vulnerabilities in the target's web application.
            3. **Website crawling**: Crawls the website and generates a sitemap.
            4. **OWASP testing**: Runs OWASP security checks against the target.
            5. **Report generation**: Generates a comprehensive security report in PDF and JSON formats.

        Args:
            pdf_path (str): The file path where the PDF security report will be saved. Defaults to 'security_report.pdf'.
            json_path (str): The file path where the JSON security report will be saved. Defaults to 'security_report.json'.

        Returns:
            None: The method saves the security reports at the specified paths.
        """
        try:
            appLogger.info("⏳ Starting EclipseRecon workflow...")

            results = {}

            subdomains = self._run_subdomain_scanner()
            if not self.is_ip:
                appLogger.info(f"🌐 Found {len(subdomains)} subdomains.")

            vulnerabilities = self._run_vulnerability_scanner(subdomains if not self.is_ip else None)
            appLogger.info(f"🔒 Detected vulnerabilities in {len(vulnerabilities)} targets.")

            sitemaps = self._run_website_spider(subdomains if not self.is_ip else None)
            appLogger.info(f"🖋️ Generated sitemaps for {len(sitemaps)} targets.")

            owasp_results = self._run_owasp_scanner(subdomains if not self.is_ip else None)
            appLogger.info(f"🏠 Completed OWASP analysis on {len(owasp_results)} targets.")

            results['subdomains'] = subdomains
            results['vulnerabilities'] = vulnerabilities
            results['sitemaps'] = sitemaps
            results['owasp'] = owasp_results

            if results:
                self._generate_security_report(
                    results=results,
                    pdf_path=pdf_path,
                    json_path=json_path
                )

        except KeyboardInterrupt:
            appLogger.info("⚠️ Execution interrupted by user. Cleaning up...")
            appLogger.info("🛑 Process terminated successfully.")

    @staticmethod
    def _is_valid_ip(target):
        """
        Determines if the target is a valid IPv4 address, optionally with a port.

        Args:
            target (str): The target string to validate.

        Returns:
            bool: True if the target is a valid IPv4 address (with or without a port), False otherwise.
        """
        ip_with_port_regex = re.compile(
            r"^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}"
            r"(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})(:\d{1,5})?$"
        )
        
        match = ip_with_port_regex.match(target)
        if not match:
            return False

        if ":" in target:
            _, port = target.rsplit(":", 1)
            if not (1 <= int(port) <= 65535):
                return False

        return True

    def _run_subdomain_scanner(self):
        """
        Initiates the subdomain scanning process if the target is a domain (not an IP address).
        This method uses the `SubdomainScanner` to discover subdomains for the target domain.

        Returns:
            list: A list of subdomains discovered during the scan. An empty list is returned if the target is an IP address.
        """
        if self.is_ip:
            appLogger.info("⚠️ Skipping subdomain scanning as the target is an IP address.")
            return []
        
        appLogger.info("🔍 Starting subdomain scanning...")
        subdomains = self.subdomainScanner.scan()
        appLogger.info(f"✅ Discovered {len(subdomains)} subdomains.")
        return subdomains

    def _run_vulnerability_scanner(self, subdomains=None):
        """
        Executes the vulnerability scanning process on the target or its subdomains, using the `WebVulnerabilityScanner`.

        Args:
            subdomains (list, optional): A list of subdomains to scan. Defaults to None. If None, the scan is performed on the target domain or IP.

        Returns:
            dict: A dictionary containing vulnerabilities detected, categorized by target or subdomain.
        """
        appLogger.info("🔧 Starting vulnerability scanning...")
        vulnerabilities = {}

        if self.is_ip:
            self.vul_scanner.base_url = f"http://{self.target}/FUZZ"
            vulnerabilities[self.target] = self.vul_scanner.start_scan(max_concurrent_requests=10)
            appLogger.info(f"🔒 Vulnerability scan completed for IP {self.target}.")
        else:
            for subdomain, _ in subdomains:
                self.vul_scanner.base_url = f"http://{subdomain}/FUZZ"
                vulnerabilities[subdomain] = self.vul_scanner.start_scan(max_concurrent_requests=10)
                appLogger.info(f"🔒 Vulnerability scan completed for subdomain {subdomain}.")
        return vulnerabilities

    def _run_website_spider(self, subdomains=None):
        """
        Crawls the target website or discovered subdomains to generate sitemaps. The method uses a spider to crawl and save sitemaps.

        Args:
            subdomains (list, optional): A list of subdomains to crawl. Defaults to None. If None, the crawl is performed on the target domain or IP.

        Returns:
            list: A list of file paths to the generated sitemap files.
        """
        appLogger.info("🧭 Starting website crawling...")
        sitemap_files = []

        if self.is_ip:
            run_spider(allowed_domains=[self.target], start_urls=[f"http://{self.target}/"] )
            sitemap_files.append(f"{self.target}_sitemap.html")
            appLogger.info(f"🖋️ Sitemap generated for IP {self.target}.")
        else:
            for subdomain, _ in subdomains:
                run_spider(allowed_domains=[subdomain], start_urls=[f"http://{subdomain}/"])
                sitemap_files.append(f"{subdomain}_sitemap.html")
                appLogger.info(f"🖋️ Sitemap generated for subdomain {subdomain}.")
        return sitemap_files

    def _run_owasp_scanner(self, subdomains=None):
        """
        Executes OWASP security testing on the target or discovered subdomains using the `OwaspSecurityScanner`.

        Args:
            subdomains (list, optional): A list of subdomains to test. Defaults to None. If None, the scan is performed on the target domain or IP.

        Returns:
            dict: A dictionary containing the OWASP scan results, categorized by target or subdomain.
        """
        appLogger.info("🚨 Starting OWASP security analysis...")
        owasp_results = {}

        if self.is_ip:
            target_url = f"http://{self.target}"
            scan_results = self.owasp_scanner.perform_full_scan(target_url=target_url)
            owasp_results[self.target] = scan_results
            appLogger.info(f"🏠 OWASP analysis completed for IP {self.target}.")
        else:
            for subdomain, _ in subdomains:
                target_url = f"http://{subdomain}"
                scan_results = self.owasp_scanner.perform_full_scan(target_url=target_url)
                owasp_results[subdomain] = scan_results
                appLogger.info(f"🏠 OWASP analysis completed for subdomain {subdomain}.")
    
        return owasp_results

    def _generate_security_report(self, results, pdf_path="security_report.pdf", json_path="security_report.json"):
        """
        Generates a comprehensive security report in PDF and JSON formats based on the results of all scanning processes.

        Args:
            results (dict): A dictionary containing the results from all scanning processes (subdomains, vulnerabilities, sitemaps, OWASP analysis).
            pdf_path (str): The file path to save the generated PDF report. Defaults to "security_report.pdf".
            json_path (str): The file path to save the generated JSON report. Defaults to "security_report.json".

        Raises:
            Exception: If the report generation fails, an exception is raised.
        """
        appLogger.info("🔖 Generating security report...")
        try:
            message = self.security_analyzer.generate_report(
                scan_results=results,
                pdf_path=pdf_path,
                json_path=json_path
            )
            appLogger.info(f"✅ Report generated successfully: {message}")
        except Exception as e:
            appLogger.error(f"❌ Failed to generate security report: {e}")

    def _print_banner(self):
        """
        Prints a welcome banner at the start of the program for EclipseRecon.
        """
        banner = f"""
        ███████╗ ██████╗██╗     ██╗██████╗ ███████╗███████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
        ██╔════╝██╔════╝██║     ██║██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
        █████╗  ██║     ██║     ██║██████╔╝███████╗█████╗  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
        ██╔══╝  ██║     ██║     ██║██╔═══╝ ╚════██║██╔══╝  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
        ███████╗╚██████╗███████╗██║██║     ███████║███████╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
        ╚══════╝ ╚═════╝╚══════╝╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝                                                                                                                                                                                                                                                        
        EclipseRecon: Advanced Ethical Hacking for Web Security Assessment  (Version: {__version__})
        """
        print(banner)


