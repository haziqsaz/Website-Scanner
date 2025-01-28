import requests
import socket
import ssl
import json
import csv
from urllib.parse import urlparse
from bs4 import BeautifulSoup


class VulnerabilityAssessmentTool:
    def __init__(self):
        self.base_url = ""
        self.results = {}

    def validate_url(self, url):
        """Validate the provided URL."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False

    def enter_url(self):
        """Prompt the user to input a valid URL."""
        while True:
            url = input("[+] Enter the URL you want to assess (e.g.: https://example.com): ")
            if self.validate_url(url):
                self.base_url = url
                self.results["URL"] = url
                print(f"[+] URL '{url}' has been set for assessment.")
                break
            else:
                print("[!] Invalid URL. Please try again.")

    def retrieve_url_data(self):
        """Retrieve basic information about the target website."""
        print("\n[+] Retrieving website data...")
        try:
            response = requests.get(self.base_url, timeout=10)
            ip_address = socket.gethostbyname(urlparse(self.base_url).netloc)

            website_info = {
                "IP Address": ip_address,
                "Status Code": response.status_code,
                "Server Headers": response.headers.get("Server", "Unknown"),
            }
            print(json.dumps(website_info, indent=2))
            self.results["Website Info"] = website_info
        except Exception as e:
            print(f"[!] Error retrieving URL data: {e}")
            self.results["Website Info"] = {"Error": str(e)}

    def validate_ssl_certificate(self):
        """Validate the SSL certificate of the target website."""
        print("\n[+] Validating SSL certificate...")
        try:
            hostname = urlparse(self.base_url).netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cert_info = {
                        "Subject": dict(x[0] for x in cert["subject"]),
                        "Issuer": dict(x[0] for x in cert["issuer"]),
                        "Valid From": cert.get("notBefore", "N/A"),
                        "Valid To": cert.get("notAfter", "N/A"),
                    }
                    self.results["SSL Certificate"] = {
                        "Details": cert_info,
                        "Status": "Valid",
                        "Recommendation": "Ensure SSL certificates are renewed before expiration.",
                    }
                    print(json.dumps(cert_info, indent=2))
        except Exception as e:
            print(f"[!] SSL validation failed: {e}")
            self.results["SSL Certificate"] = {"Status": "Failed", "Error": str(e)}

    def scan_open_ports(self):
        """Scan common open ports on the target website."""
        print("\n[+] Scanning for open ports...")
        hostname = urlparse(self.base_url).netloc
        common_ports = [80, 443, 21, 22, 25, 110, 8080]
        open_ports = []
        for port in common_ports:
            try:
                with socket.create_connection((hostname, port), timeout=1):
                    open_ports.append(port)
            except:
                pass

        if open_ports:
            print(f"[+] Open ports detected: {open_ports}")
        else:
            print("[!] No open ports detected.")

        self.results["Open Ports"] = {
            "Ports": open_ports,
            "Recommendation": "Close unnecessary ports and use a firewall to restrict access."
        }

    def detect_sql_injection(self):
        """Detect potential SQL injection vulnerabilities."""
        print("\n[+] Scanning for SQL Injection vulnerabilities...")
        test_payloads = ["' OR '1'='1", "'; DROP TABLE users; --"]
        vulnerable = False

        for payload in test_payloads:
            test_url = f"{self.base_url}?test={payload}"
            try:
                response = requests.get(test_url, timeout=10)
                if "error" in response.text.lower() or "syntax" in response.text.lower():
                    print(f"[!] Potential SQL Injection detected with payload: {payload}")
                    vulnerable = True
                    break
            except Exception as e:
                print(f"[!] Error testing payload: {e}")

        self.results["SQL Injection"] = {
            "Vulnerable": vulnerable,
            "Recommendation": (
                "If vulnerable, use parameterized queries and input validation. "
                "If secure, maintain regular security audits."
            ),
        }

    def detect_xss(self):
        """Detect potential XSS vulnerabilities."""
        print("\n[+] Scanning for XSS vulnerabilities...")
        test_payload = "<script>alert('XSS')</script>"
        try:
            response = requests.get(f"{self.base_url}?test={test_payload}", timeout=10)
            if test_payload in response.text:
                print("[!] Potential XSS vulnerability detected!")
                self.results["XSS"] = {
                    "Vulnerable": True,
                    "Recommendation": "Sanitize inputs and implement Content Security Policy (CSP).",
                }
            else:
                print("[+] No XSS vulnerability detected.")
                self.results["XSS"] = {"Vulnerable": False}
        except Exception as e:
            print(f"[!] Error testing XSS: {e}")
            self.results["XSS"] = {"Error": str(e)}

    def fetch_cve_data(self):
        """Fetch relevant CVE data based on the detected server software."""
        print("\n[+] Fetching CVE data based on server software...")
        if "Website Info" not in self.results or "Server Headers" not in self.results["Website Info"]:
            print("[!] Server software information not available. Run 'Retrieve URL Data' first.")
            return

        server_software = self.results["Website Info"].get("Server Headers", "Unknown")
        if server_software == "Unknown":
            print("[!] Unable to determine server software. CVE search cannot proceed.")
            return

        search_query = server_software.split("/")[0]  # Extract software name
        print(f"[+] Searching CVEs for: {search_query}...")

        try:
            cve_url = f"https://cve.circl.lu/api/search/{search_query}"
            response = requests.get(cve_url, timeout=10)

            if response.status_code == 200:
                cve_data = response.json().get("results", [])
                if not cve_data:
                    print(f"[!] No CVEs found for {search_query}.")
                    self.results["CVE Data"] = {"Search Query": search_query, "Results": "No CVEs found."}
                else:
                    print(f"[+] Found {len(cve_data)} CVEs for {search_query}. Displaying the first 5:")
                    relevant_cves = cve_data[:5]
                    for cve in relevant_cves:
                        print(f"\nCVE ID: {cve.get('id')}")
                        print(f"Summary: {cve.get('summary')}")
                        print(f"Published Date: {cve.get('Published')}\n")

                    self.results["CVE Data"] = {
                        "Search Query": search_query,
                        "Results": relevant_cves,
                    }
            else:
                print(f"[!] Failed to fetch CVE data (HTTP {response.status_code}).")
                self.results["CVE Data"] = {"Search Query": search_query, "Error": f"HTTP {response.status_code}"}
        except Exception as e:
            print(f"[!] Error fetching CVE data: {e}")
            self.results["CVE Data"] = {"Search Query": search_query, "Error": str(e)}

    def display_results(self):
        """Display all scan results in a friendly format."""
        print("\n[+] Displaying Results:")
        if not self.results:
            print("[!] No results available.")
        for category, result in self.results.items():
            print(f"\n{category}:\n")
            if isinstance(result, dict):
                for key, value in result.items():
                    print(f"  {key}: {value}")
            else:
                print(f"  {result}")
        print("\n[+] End of results.")

    def save_report(self):
        """Save the scan results to a file."""
        print("\n[+] Choose a report format:")
        print("1. JSON")
        print("2. CSV")
        print("3. Plain Text")
        choice = input("Enter your choice: ")

        try:
            if choice == "1":
                with open("vulnerability_report.json", "w") as file:
                    json.dump(self.results, file, indent=2)
                print("[+] Report saved as vulnerability_report.json")
            elif choice == "2":
                with open("vulnerability_report.csv", "w", newline="") as file:
                    writer = csv.writer(file)
                    for key, value in self.results.items():
                        writer.writerow([key, json.dumps(value, indent=2)])
                print("[+] Report saved as vulnerability_report.csv")
            elif choice == "3":
                with open("vulnerability_report.txt", "w") as file:
                    for key, value in self.results.items():
                        file.write(f"{key}:\n{json.dumps(value, indent=2)}\n\n")
                print("[+] Report saved as vulnerability_report.txt")
            else:
                print("[!] Invalid choice. Report not saved.")
        except Exception as e:
            print(f"[!] Error saving report: {e}")

    def menu(self):
        """Display the main menu for user interaction."""
        options = {
            "1": ("Retrieve URL Data", self.retrieve_url_data),
            "2": ("Validate SSL Certificate", self.validate_ssl_certificate),
            "3": ("Scan Open Ports", self.scan_open_ports),
            "4": ("Detect SQL Injection", self.detect_sql_injection),
            "5": ("Detect XSS", self.detect_xss),
            "6": ("Fetch CVE Data", self.fetch_cve_data),
            "7": ("Display Results", self.display_results),
            "8": ("Save Report", self.save_report),
            "0": ("Exit", exit),
        }

        while True:
            print("\n[+] Select a task:")
            for key, (desc, _) in options.items():
                print(f"{key}. {desc}")
            choice = input("Enter your choice: ")
            if choice in options:
                options[choice][1]()
            else:
                print("[!] Invalid choice. Please try again.")


if __name__ == "__main__":
    tool = VulnerabilityAssessmentTool()
    tool.enter_url()
    tool.menu()
