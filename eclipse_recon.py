import re
from subdomain_scanner import SubdomainScanner
from vulnerability_scanner import WebVulnerabilityScanner
from website_spider import WebsiteStructureSpider, run_spider
from owasp_security_scanner import OwaspSecurityScanner
from utils.logger import appLogger


class EclipseRecon:
    def __init__(self, target, scan_depth="normal", ipv6=False, threads=10, proxies=None):
        """
        Initializes EclipseRecon with the target (domain or IP), scan depth, IPv6 preference, thread count, and optional proxies.

        Args:
            target (str): Target domain or IP for the recon process.
            scan_depth (str): Depth of the subdomain scan (e.g., "normal", "deep").
            ipv6 (bool): Whether to include IPv6 subdomains in the scan.
            threads (int): Number of concurrent threads for scanning.
            proxies (dict, optional): Proxies for OWASP ZAP and other tools (default: None).
        """
        self.target = target
        self.scan_depth = scan_depth
        self.ipv6 = ipv6
        self.threads = threads
        self.proxies = proxies or {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
        self.results = {}

        # Detect if the target is a domain or an IP address
        self.is_ip = self._is_valid_ip(target)
        if self.is_ip:
            appLogger.info(f"Target {target} is identified as an IP address.")
        else:
            appLogger.info(f"Target {target} is identified as a domain.")

    @staticmethod
    def _is_valid_ip(target):
        """
        Checks if the target is a valid IP address.

        Args:
            target (str): The target to check.

        Returns:
            bool: True if the target is a valid IP address, False otherwise.
        """
        ip_regex = re.compile(
            r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"  # IPv4 regex
        )
        return bool(ip_regex.match(target))

    def _run_subdomain_scanner(self):
        """Private method to run subdomain scanner. Skips if the target is an IP."""
        if self.is_ip:
            appLogger.info("Skipping subdomain scanning as the target is an IP address.")
            return []
        
        scanner = SubdomainScanner(
            domain=self.target,
            scan_depth=self.scan_depth,
            ipv6=self.ipv6,
            threads=self.threads
        )
        subdomains = scanner.scan()
        self.results['subdomains'] = subdomains
        return subdomains

    def _run_vulnerability_scanner(self, subdomains=None):
        """Private method to run vulnerability scanner."""
        vul_scanner = WebVulnerabilityScanner(base_url="http://FUZZ")
        vulnerabilities = {}

        # If target is an IP, scan it directly
        if self.is_ip:
            vul_scanner.base_url = f"http://{self.target}/FUZZ"
            vulnerabilities[self.target] = vul_scanner.start_scan(max_concurrent_requests=10)
        else:
            for subdomain, _ in subdomains:
                vul_scanner.base_url = f"http://{subdomain}/FUZZ"
                vulnerabilities[subdomain] = vul_scanner.start_scan(max_concurrent_requests=10)
        
        self.results['vulnerabilities'] = vulnerabilities
        return vulnerabilities

    def _run_website_spider(self, subdomains=None):
        """Private method to run website structure spider."""
        sitemap_files = []

        # If target is an IP, crawl it directly
        if self.is_ip:
            WebsiteStructureSpider.allowed_domains = [self.target]
            WebsiteStructureSpider.start_urls = [f"http://{self.target}/"]
            run_spider()
            sitemap_files.append(f"{self.target}_sitemap.html")
        else:
            for subdomain, _ in subdomains:
                WebsiteStructureSpider.allowed_domains = [subdomain]
                WebsiteStructureSpider.start_urls = [f"http://{subdomain}/"]
                run_spider()
                sitemap_files.append(f"{subdomain}_sitemap.html")
        
        self.results['sitemaps'] = sitemap_files
        return sitemap_files

    def _run_owasp_scanner(self, subdomains=None):
        """Private method to run OWASP ZAP security scanner."""
        owasp_results = {}

        # If target is an IP, scan it directly
        if self.is_ip:
            target_url = f"http://{self.target}"
            owasp_scanner = OwaspSecurityScanner(target_url=target_url, proxies=self.proxies)
            appLogger.info(f"Running OWASP scan on {target_url}...")
            scan_results = owasp_scanner.perform_full_scan()
            owasp_results[self.target] = scan_results
        else:
            for subdomain, _ in subdomains:
                target_url = f"http://{subdomain}"
                owasp_scanner = OwaspSecurityScanner(target_url=target_url, proxies=self.proxies)
                appLogger.info(f"Running OWASP scan on {target_url}...")
                scan_results = owasp_scanner.perform_full_scan()
                owasp_results[subdomain] = scan_results
        
        self.results['owasp'] = owasp_results
        return owasp_results

    def execute(self):
        """Public method to execute the EclipseRecon workflow."""
        print("🚀 Starting EclipseRecon workflow...")
        
        subdomains = self._run_subdomain_scanner()
        if not self.is_ip:
            print(f"🔎 Found {len(subdomains)} subdomains.")

        vulnerabilities = self._run_vulnerability_scanner(subdomains if not self.is_ip else None)
        print(f"🛠️ Detected vulnerabilities in {len(vulnerabilities)} targets.")
        
        sitemaps = self._run_website_spider(subdomains if not self.is_ip else None)
        print(f"🌐 Generated sitemaps for {len(sitemaps)} targets.")
        
        owasp_results = self._run_owasp_scanner(subdomains if not self.is_ip else None)
        print(f"🛡️ Completed OWASP analysis on {len(owasp_results)} targets.")

if __name__ == "__main__":
    recon = EclipseRecon(
        target="192.168.11.130",  # Change to a domain or IP as needed
        scan_depth="test",
        ipv6=False,
        threads=10,
        proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
    )
    recon.execute()