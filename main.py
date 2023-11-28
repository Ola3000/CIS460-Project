from flask import Flask, render_template, request, jsonify
import nmap
import vulners

# Creating a Flask web application instance
app = Flask(__name__)

# Initializing nmap PortScanner and Vulners API with API key
nm = nmap.PortScanner()
api_key = "H0BH38KRE6F6WY5309EOZXLV6M80AV82SYNGIQ4QB9BURKMHZPNNLCCXVNV139VB"  
vulners_api = vulners.Vulners(api_key)

# Route to serve the main page
@app.route('/')
def index():
    return render_template('GUI.html')

# Route to handle nmap scanning request
@app.route('/run-nmap', methods=['POST'])
def run_nmap():
    data = request.json
    ip_address = data['ipAddress']
    ports = '22-443' # Defines the port range for scanning

    # Runs the nmap scan
    nm.scan(ip_address, ports)
    scan_results = []

    # Processes scan results
    for host in nm.all_hosts():
        host_info = {
            'host': host,
            'hostname': nm[host].hostname(),
            'state': nm[host].state(),
            'services': []
        }

        # Looping through each protocol in the scan results
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                service = nm[host][proto][port]['name']
                service_version = nm[host][proto][port]['product']
                vulnerabilities = []

                # Searching for vulnerabilities if service version is available
                if service_version:
                    search_query = f"{service} {service_version}"
                    vulnerabilities_response = vulners_api.find_all(search_query)

                    # Adding found vulnerabilities to the results
                    if vulnerabilities_response:
                        for vuln in vulnerabilities_response:
                            vulnerabilities.append({
                                'title': vuln['title'],
                                'cvss_score': vuln.get('cvss', {}).get('score', 'N/A'),
                                'link': vuln.get('href')
                            })

                host_info['services'].append({
                    'port': port,
                    'state': nm[host][proto][port]['state'],
                    'service': service,
                    'version': service_version,
                    'vulnerabilities': vulnerabilities
                })

        scan_results.append(host_info)

    # Returns JSON response with scan results
    return jsonify(scan_results)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
