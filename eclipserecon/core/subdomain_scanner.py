import dns.resolver
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from eclipserecon.utils.logger import appLogger
import os

class SubdomainScanner:
    """
    This class scans subdomains of a given domain using predefined subdomain wordlists
    based on the scan depth level and resolves DNS queries using custom or default nameservers.

    Attributes:
        domain (str): The target domain for scanning.
        scan_depth (str): The depth of the scan ('test', 'basic', 'normal', 'deep').
        ipv6 (bool): Specifies whether to resolve AAAA (IPv6) records instead of A (IPv4) records.
        threads (int): Number of threads to use for scanning.
        resolver (dns.resolver.Resolver): Configured Resolver object.
        record_type (str): DNS record type to resolve ('A' or 'AAAA').
    """

    def __init__(self, domain, scan_depth="normal", resolver_list=None, ipv6=False, threads=10):
        """
        Initializes the SubdomainScanner class with the specified parameters.

        Args:
            domain (str): Target domain for scanning.
            scan_depth (str): Depth of the scan ('basic', 'normal', 'deep'). Defaults to 'normal'.
            resolver_list (str, optional): Path to the nameservers file. Defaults to None.
            ipv6 (bool, optional): Specifies whether to resolve AAAA (IPv6) records. Defaults to False.
            threads (int, optional): Number of threads to use for scanning. Defaults to 10.
        """
        self.domain = domain
        self.scan_depth = scan_depth.lower()
        appLogger.info(f"💻 Target domain set to: {domain}")
        appLogger.info(f"🔍 Scan depth level: {scan_depth}")
        self.wordlist = self._select_wordlist()
        self.ipv6 = ipv6
        self.threads = threads
        appLogger.info(f"⚙️ Threads configured: {threads}")
        self.resolver = self._setup_resolver(resolver_list)
        self.record_type = 'AAAA' if ipv6 else 'A'
        appLogger.info(f"📡 DNS record type: {self.record_type}")

    def scan(self):
        """
        Performs the subdomain scanning using multiple threads and displays progress with tqdm.

        Returns:
            list: A list of tuples containing subdomains and their resolved IP addresses.
                  Each tuple has the format (subdomain, [list of IPs]) or None if resolution fails.
        """
        appLogger.info(f"🔍 Initiating subdomain scan for: {self.domain} using {self.threads} threads")
        results = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            with tqdm(total=len(self.wordlist), desc="🚀 Scanning", unit="subdomain") as progress_bar:
                futures = {executor.submit(self._scan_domain, subdomain): subdomain for subdomain in self.wordlist}
                for future in futures:
                    result = future.result()
                    if result:
                        results.append(result)
                    progress_bar.update(1)
        
        appLogger.info(f"✅ Scan completed for: {self.domain}")
        return results

    def _scan_domain(self, subdomain):
        """
        Scans a specific subdomain and resolves its IP address.

        Args:
            subdomain (str): The subdomain to scan.

        Returns:
            tuple: A tuple containing the full subdomain and a list of resolved IP addresses,
                   or None if the subdomain cannot be resolved.
        """
        full_domain = f"{subdomain}.{self.domain}"
        appLogger.debug(f"🔎 Scanning subdomain: {full_domain}")
        try:
            answers = self.resolver.resolve(full_domain, self.record_type)
            return (full_domain, [answer.address for answer in answers])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            return None
        
    def _select_wordlist(self):
        """
        Selects the appropriate wordlist file based on the scan depth level.

        Returns:
            list: List of words from the selected wordlist file.

        Raises:
            ValueError: If the scan depth is invalid.
        """
        depth_mapping = {
            "test": "assets/dns/subdomains-test.txt",
            "basic": "assets/dns/subdomains-5000.txt",
            "normal": "assets/dns/subdomains-20000.txt",
            "deep": "assets/dns/subdomains-110000.txt"
        }

        if self.scan_depth not in depth_mapping:
            appLogger.error(f"❌ Invalid scan depth: {self.scan_depth}")
            raise ValueError(f"Invalid scan depth: {self.scan_depth}. Choose from 'test', 'basic', 'normal', or 'deep'.")

        relative_path = depth_mapping[self.scan_depth]
        current_directory = os.path.dirname(os.path.abspath(__file__))
        selected_file = os.path.join(current_directory, relative_path)
    
        appLogger.info(f"📂 Selected wordlist: {relative_path}")
        return self._load_file(selected_file)

    def _load_file(self, path):
        """
        Loads the content of a file and returns it as a list of lines.

        Args:
            path (str): Path to the file.

        Returns:
            list: List of lines from the file.

        Raises:
            FileNotFoundError: If the file cannot be opened.
        """
        if not os.path.exists(path):
            appLogger.error(f"❌ File not found: {path}")
            raise FileNotFoundError(f"File not found: {path}")
        with open(path, 'r') as file:
            return file.read().splitlines()

    def _setup_resolver(self, resolver_list):
        """
        Configures the Resolver object with an optional list of nameservers.
        If no list is provided, it uses the default nameservers file.

        Args:
            resolver_list (str, optional): Path to the nameservers file. Defaults to None.

        Returns:
            dns.resolver.Resolver: Configured Resolver object.

        Raises:
            FileNotFoundError: If the nameservers file cannot be opened.
        """
        appLogger.info("🔧 Setting up DNS resolver")
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1
        resolver.lifetime = 1

        if resolver_list is None:
            resolver_list = "assets/dns/nameservers.txt"
            appLogger.info(f"📜 Using default nameservers file: {resolver_list}")

        current_directory = os.path.dirname(os.path.abspath(__file__))
        resolver_list_path = os.path.join(current_directory, resolver_list)
        appLogger.info(f"📂 Trying to load nameservers file")

        if not os.path.exists(resolver_list_path):
            appLogger.error(f"❌ Unable to read nameservers file: {resolver_list_path}")
            raise FileNotFoundError(f"Unable to read nameservers file: {resolver_list_path}")

        with open(resolver_list_path, 'r') as file:
            resolver.nameservers = file.read().splitlines()

        return resolver

if __name__ == "__main__":
    scanner = SubdomainScanner(
        domain="udemy.com",
        scan_depth="test",  # Options: "basic", "normal", "deep"
        ipv6=False,
        threads=10
    )
    scanner.scan()