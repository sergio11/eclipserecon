import asyncio
import aiohttp
import os
from urllib.parse import urlparse
from utils.logger import appLogger
from tqdm.asyncio import tqdm

class WebContentDiscovery:
    """
    Class for web content discovery by fuzzing login endpoints using a predefined wordlist
    (assets/webcontent/logins.fuzz.txt). The scan is done asynchronously for improved speed.

    Attributes:
        base_url (str): The base URL to fuzz with words from the wordlist.
        extensions (list): List of extensions to append to each word.
        timeout (int): Maximum wait time for a response from the server.
        follow_redirects (bool): Whether to follow HTTP redirects.
        verify_ssl (bool): Whether to verify the SSL certificate.
        user_agent (str): The user-agent string to use for requests.
    """
    
    def __init__(self, base_url, extensions=[], timeout=5, follow_redirects=False, verify_ssl=False):
        """
        Initializes WebContentDiscovery with the provided parameters.

        Args:
            base_url (str): Base URL for fuzzing login endpoints.
            extensions (list, optional): Extensions to append to words. Defaults to empty list.
            timeout (int, optional): Timeout for requests. Defaults to 5 seconds.
            follow_redirects (bool, optional): Whether to follow redirects. Defaults to False.
            verify_ssl (bool, optional): Whether to verify SSL certificates. Defaults to False.
        """
        self.base_url = base_url
        self.extensions = extensions
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"

    def start_scan(self, max_concurrent_requests=10):
        """Starts the scan process synchronously and returns the scan results.

        Args:
            max_concurrent_requests (int): The maximum number of simultaneous requests (concurrency).
        """
        appLogger.info(f"🔥 Starting web content discovery for: {self.base_url}")
        result = asyncio.run(self._run_scan(max_concurrent_requests))
        appLogger.success(f"✅ Scan complete.")
        return result

    async def _run_scan(self, max_concurrent_requests):
        """Performs the web content discovery scan asynchronously.

        Args:
            max_concurrent_requests (int): Maximum number of simultaneous requests.
        """
        urls = self._generate_urls()
        semaphore = asyncio.Semaphore(max_concurrent_requests)  # Control concurrency with semaphore
        async with aiohttp.ClientSession(headers={'User-Agent': self.user_agent}, connector=aiohttp.TCPConnector(ssl=self.verify_ssl)) as session:
            tasks = []
            for url in tqdm(urls, desc="💻 Scanning login endpoints", unit="url"):
                task = asyncio.create_task(self._fetch_and_log(session, url, semaphore))
                tasks.append(task)
            responses = await asyncio.gather(*tasks)
            return self._process_responses(responses)

    async def _fetch_and_log(self, session, url, semaphore):
        """Makes an HTTP request to the specified URL and logs the response.

        Args:
            session (aiohttp.ClientSession): The HTTP session used for making requests.
            url (str): The URL to request.
            semaphore (asyncio.Semaphore): Semaphore to limit concurrent requests.

        Returns:
            tuple: URL, HTTP status code, response content or error message.
        """
        async with semaphore:
            try:
                response = await session.get(url, allow_redirects=self.follow_redirects, timeout=aiohttp.ClientTimeout(total=self.timeout))
                return (url, response.status, await response.text())
            except Exception as e:
                return (url, None, str(e))

    def _generate_urls(self):
        """Generates login URLs by fuzzing the base URL with words from the logins.fuzz.txt file and appending extensions.

        Returns:
            list: List of generated URLs for fuzzing.
        """
        urls = []
        wordlist_path = "assets/webcontent/logins.fuzz.txt"  # Predefined wordlist for login fuzzing
        try:
            with open(wordlist_path, 'r') as file:
                for line in file:
                    word = line.strip()
                    base = self.base_url.replace("FUZZ", word)
                    urls.append(base)
                    for ext in self.extensions:
                        urls.append(f"{base}{ext}")
            appLogger.info(f"🔎 {len(urls)} login URLs generated for fuzzing.")
        except FileNotFoundError:
            appLogger.error(f"❌ The wordlist file '{wordlist_path}' was not found.")
            raise
        return urls
    
    def _process_responses(self, responses):
        """Processes the responses from the scan and returns the found URLs.

        Args:
            responses (list): List of responses from the scan (URL, status, content).

        Returns:
            list: A list of URLs that returned HTTP status 200.
        """
        found_urls = []
        for url, status, content in responses:
            if status == 200:
                found_urls.append(url)
        return found_urls


if __name__ == "__main__":
    scanner = WebContentDiscovery(
        base_url="http://192.168.138.129:8080/login/FUZZ",  # Replace FUZZ with wordlist entries
        extensions=[".php", ".bak", ".old", ".zip"], 
        follow_redirects=True,
        verify_ssl=False
    )
    results = scanner.start_scan(max_concurrent_requests=20)
    # Print the results (list of found URLs)
    print("Found URLs:")
    for url in results:
        print(url)