import nmap
import vulners
import warnings


warnings.filterwarnings("ignore", category=DeprecationWarning, module='vulners')

# Initialize nmap PortScanner
nm = nmap.PortScanner()


api_key = "H0BH38KRE6F6WY5309EOZXLV6M80AV82SYNGIQ4QB9BURKMHZPNNLCCXVNV139VB"  
vulners_api = vulners.Vulners(api_key)

# Define the target and the ports you want to scan
target = '207.153.45.197'  # Change this since it's my (mohamed) ip address
ports = '22-443'  # Replace this with the desired port range

# Scan the target
nm.scan(target, ports)

# Iterate over the scan results
for host in nm.all_hosts():
    print(f'----------------------------------------------------')
    print(f'Host : {host} ({nm[host].hostname()})')
    print(f'State : {nm[host].state()}')

    for proto in nm[host].all_protocols():
        print(f'----------')
        print(f'Protocol : {proto}')

        lport = nm[host][proto].keys()
        for port in lport:
            service = nm[host][proto][port]['name']
            service_version = nm[host][proto][port]['product']
            if service_version:
                print(f'port : {port}\tstate : {nm[host][proto][port]["state"]}\tService: {service}\tVersion: {service_version}')

                # Build the search query
                search_query = f"{service} {service_version}"

                # Queries the Vulners database for vulnerabilities using find_all()
                vulnerabilities_response = vulners_api.find_all(search_query)

                # Checks if the response contains any vulnerabilities
                if vulnerabilities_response:
                    for vuln in vulnerabilities_response:
                        print(f"Vulnerability: {vuln['title']}")
                        print(f"CVSS: {vuln.get('cvss', {}).get('score', 'N/A')}")
                        print(f"Link: {vuln.get('href')}")
                        print("---------------------------------")
                else:
                    print("No vulnerabilities found or error in response.")
