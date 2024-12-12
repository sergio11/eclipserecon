from eclipserecon.eclipse_recon import EclipseRecon

def main():
    recon = EclipseRecon(
        target="192.168.11.130:3000",
        scan_depth="test",
        ipv6=False,
        threads=10,
        proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
    )
    recon.execute()

if __name__ == "__main__":
    main()
   