import scrapy
import networkx as nx
from urllib.parse import urljoin
from pyvis.network import Network
from scrapy.crawler import CrawlerProcess

class WebsiteStructureSpider(scrapy.Spider):
    """
    A Scrapy Spider for mapping the structure of a website.

    Attributes:
        name (str): Name of the spider.
        allowed_domains (list): List of domains allowed for crawling.
        start_urls (list): List of starting URLs for the spider.
        tree (networkx.DiGraph): A directed graph representing the website's structure.
    """
    name = "website_structure"
    allowed_domains = ["192.168.11.130"]
    start_urls = ["http://192.168.11.130:8899/a1.html"]

    def __init__(self):
        """
        Initializes the spider and creates a directed graph to store the website structure.
        """
        super().__init__()
        self.tree = nx.DiGraph()

    def parse(self, response):
        """
        Parses the HTTP response, extracts links, and adds them to the graph.

        Args:
            response (scrapy.http.Response): The response object containing the page content.
        """
        current_url = response.url
        # Add the current page to the graph with its title (or "No Title" if none exists)
        self.tree.add_node(current_url, title=response.css('title::text').get(default="No Title"))
        # Extract all anchor links and construct absolute URLs
        for href in response.css('a::attr(href)').getall():
            full_url = urljoin(current_url, href)
            # Add edges between the current page and linked pages
            if not self.tree.has_edge(current_url, full_url):
                self.tree.add_edge(current_url, full_url)
                # Continue crawling the linked page
                yield scrapy.Request(full_url, callback=self.parse)

    def closed(self, reason):
        """
        Called when the spider finishes its execution. Generates and saves an interactive sitemap graph.

        Args:
            reason (str): Reason why the spider was closed.
        """
        output_path = "sitemap.html"
        self.generate_sitemap_graph(self.tree, output_path)
        self.logger.info(f"Sitemap saved to {output_path}")

    def generate_sitemap_graph(self, graph, output_file):
        """
        Generates an interactive graph of the website's structure and saves it as an HTML file.

        Args:
            graph (networkx.DiGraph): The directed graph representing the website's structure.
            output_file (str): Path to save the generated HTML file.
        """
        net = Network(height="750px", width="100%", bgcolor="#222222", font_color="white", directed=True)
        net.from_nx(graph)
        # Configure graph physics for better visualization
        net.repulsion(node_distance=200, central_gravity=0.3, spring_length=200, spring_strength=0.05, damping=0.09)
        net.toggle_physics(True)
        # Add titles and links to the nodes
        for node in graph.nodes:
            node_url = node
            html_link = f"<a href='{node_url}' target='_blank'>{node_url}</a>"
            if "title" in graph.nodes[node]:
                html_link += f"<br><b>Title:</b> {graph.nodes[node]['title']}"
            net.get_node(node)["title"] = html_link
        # Save the graph to an HTML file
        net.save_graph(output_file)

def run_spider():
    """
    Runs the WebsiteStructureSpider programmatically without using the CLI.
    """
    process = CrawlerProcess(settings={
        "USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        "LOG_LEVEL": "INFO",
    })
    process.crawl(WebsiteStructureSpider)
    process.start()

if __name__ == "__main__":
    run_spider()