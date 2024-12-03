import dns.resolver
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from utils.logger import appLogger

class SubdomainScanner:
    """
    This class scans subdomains of a given domain using a wordlist and optionally a custom list of nameservers.

    Attributes:
        domain (str): The target domain for scanning.
        wordlist (list): A list of words to generate subdomains.
        ipv6 (bool): Specifies whether to resolve AAAA (IPv6) records instead of A (IPv4) records.
        threads (int): Number of threads to use for scanning.
        resolver (dns.resolver.Resolver): Configured Resolver object.
        record_type (str): DNS record type to resolve ('A' or 'AAAA').
    """

    def __init__(self, domain, wordlist, resolver_list=None, ipv6=False, threads=10):
        """
        Initializes the SubdomainScanner class with the specified parameters.

        Args:
            domain (str): Target domain for scanning.
            wordlist (str): Path to the wordlist file to generate subdomains.
            resolver_list (str, optional): Path to the nameservers file. Defaults to None.
            ipv6 (bool, optional): Specifies whether to resolve AAAA (IPv6) records. Defaults to False.
            threads (int, optional): Number of threads to use for scanning. Defaults to 10.
        """
        self.domain = domain
        appLogger.info(f"💻 Target domain set to: {domain}")
        self.wordlist = self._load_file(wordlist)
        self.ipv6 = ipv6
        self.threads = threads
        appLogger.info(f"⚙️ Threads configured: {threads}")
        self.resolver = self._setup_resolver(resolver_list)
        self.record_type = 'AAAA' if ipv6 else 'A'
        appLogger.info(f"📡 DNS record type: {self.record_type}")

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
        appLogger.info(f"📂 Loading file: {path}")
        try:
            with open(path, 'r') as file:
                return file.read().splitlines()
        except FileNotFoundError:
            appLogger.error(f"❌ File not found: {path}")
            raise FileNotFoundError(f"Unable to open file: {path}")

    def _setup_resolver(self, resolver_list):
        """
        Configures the Resolver object with an optional list of nameservers.

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
        if resolver_list:
            appLogger.info(f"📜 Using custom nameserver list: {resolver_list}")
            try:
                with open(resolver_list, 'r') as file:
                    resolver.nameservers = file.read().splitlines()
            except FileNotFoundError:
                appLogger.error(f"❌ Unable to read nameservers file: {resolver_list}")
                raise FileNotFoundError(f"Unable to read nameservers file: {resolver_list}")
        return resolver

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

if __name__ == "__main__":
    scanner = SubdomainScanner(
        domain="udemy.com",
        wordlist="subdomains.txt",
        resolver_list="nameservers.txt",
        ipv6=False,
        threads=10
    )
    scanner.scan()