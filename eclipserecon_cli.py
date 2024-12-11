import argparse
from eclipserecon import __version__
from eclipserecon.utils.logger import appLogger
from eclipserecon import EclipseRecon
from dotenv import load_dotenv

def main():
    load_dotenv()

    # Create the argument parser
    parser = argparse.ArgumentParser(description="EclipseRecon: Web Reconnaissance & Security Analysis Tool")
    
    # Add arguments to configure the scan
    parser.add_argument('--target', type=str, required=True, help="The target domain or IP to scan (e.g., example.com or 192.168.1.1).")
    parser.add_argument('--scan_depth', type=str, choices=['test', 'basic', 'normal', 'deep'], default='normal',
                        help="Scan depth: 'test', 'basic', 'normal', 'deep' (default: 'normal').")
    parser.add_argument('--ipv6', action='store_true', help="Enable IPv6 scanning (default: False).")
    parser.add_argument('--threads', type=int, default=10, help="Number of threads for scanning (default: 10).")
    parser.add_argument('--proxies', type=str, help="Proxy settings for the OWASP scanner (e.g., http://proxy:8080).")
    
    # Output options
    parser.add_argument('--pdf_report', type=str, default='security_report.pdf', help="Path to save the PDF report (default: 'security_report.pdf').")
    parser.add_argument('--json_report', type=str, default='security_report.json', help="Path to save the JSON report (default: 'security_report.json').")
    
    # Parse the arguments
    args = parser.parse_args()

    # Start the scan and report generation process
    try:
        recon = EclipseRecon(
            target=args.target,
            scan_depth=args.scan_depth,
            ipv6=args.ipv6,
            threads=args.threads,
            proxies=args.proxies
        )

        recon.execute(
            pdf_path=args.pdf_report,
            json_path=args.json_report
        )
        
    except Exception as e:
        appLogger.error(f"❌ An error occurred: {e}")
        
if __name__ == "__main__":
    main()