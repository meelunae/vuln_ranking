import argparse
import csv
import xml.etree.ElementTree as ET
import json
import kev
import requests
import subprocess
import time

REQUEST_DELAY = 6  # Sleep time between requests

"""
Query the API provided by NIST for the National Vulnerability Database.
This database offers helpful data for our use case like the vulnerability description and exploitability status.
"""
def fetch_cve_description(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Connection": "keep-alive",
        }

        session = requests.Session()
        response = session.get(url, headers=headers)
        response.raise_for_status()  # This will raise an exception for HTTP errors

        # Check if the response content is empty
        if not response.text.strip():
            print(f"⚠️ No data returned for {cve_id}")
            return {"title": cve_id, "description": "No description available", "cvss": "N/A", "references": []}

        data = response.json()

        if "vulnerabilities" not in data or not data["vulnerabilities"]:
            print(f"⚠️ No vulnerabilities found for {cve_id}")
            return {"title": cve_id, "description": "No data found", "cvss": "N/A", "references": []}

        vuln = data["vulnerabilities"][0]["cve"]
        title = vuln["id"]
        description = vuln["descriptions"][0]["value"] if vuln["descriptions"] else "No description available"

        # Extract CVSS score (use the 3.1 score if available)
        cvss = vuln["metrics"].get("cvssMetricV31", [])
        if cvss:
            cvss_score = cvss[0]["cvssData"]["baseScore"]
        else:
            cvss_score = "N/A"

        exploitability_in_nvd = any(
            "Exploit" in ref.get("tags", []) for ref in vuln.get("references", [])
        )
        return {
            "title": title,
            "description": description,
            "cvss": cvss_score,
            "exploitability": exploitability_in_nvd
        }

    except requests.exceptions.RequestException as e:
        print(f"⚠️ Error fetching CVE details for {cve_id}: {e}")
        return {"title": cve_id, "description": "Error fetching details", "cvss": "N/A", "references": []}
    except (KeyError, IndexError, ValueError) as e:
        print(f"⚠️ Error parsing data for {cve_id}: {e}")
        return {"title": cve_id, "description": "Error parsing details", "cvss": "N/A", "references": []}
    finally:
        time.sleep(REQUEST_DELAY)  # Respect rate limits


"""
This function leverages a very interesting tool provided by Offensive Security as a way
to query their database. More information on the CLI tool can be found at https://www.exploit-db.com/searchsploit
"""
def query_exploitdb_for_exploits(cve):
    try:
        result = subprocess.run(
            ["searchsploit", "--cve", cve, "-j"],
            capture_output=True,
            text=True,
            check=True
        )
        data = json.loads(result.stdout)
        return bool(data.get("RESULTS_EXPLOIT"))  # True if exploits exist
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        print(f"Error in query_exploitdb_for_exploits: {e}")
        return False  # Assume not exploitable if an error occurs

"""
Parses the XML produced as output of a nmap scan
launched with the following command: nmap -sV -p [PORTS] --script vulners [HOST] -oX [OUTPUT_FILE]
"""
def parse_nmap_output_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    vulnerabilities = []

    for host in root.findall(".//host"):
        ip_elem = host.find(".//address")
        ip = ip_elem.attrib["addr"] if ip_elem is not None else "Unknown IP"

        for port in host.findall(".//ports/port"):
            portid = port.attrib.get("portid", "Unknown Port")
            service_elem = port.find(".//service")
            service_name = service_elem.attrib.get("name", "Unknown Service") if service_elem is not None else "Unknown Service"

            # Find Vulners script data
            script_elem = port.find(".//script[@id='vulners']")
            if script_elem is not None:
                for table in script_elem.findall(".//table"):
                    id_elem = table.find(".//elem[@key='id']")
                    type_elem = table.find(".//elem[@key='type']")
                    cvss_elem = table.find(".//elem[@key='cvss']")

                    if id_elem is not None and type_elem is not None and type_elem.text == "cve":
                        try:
                            cvss_score = float(cvss_elem.text) if cvss_elem is not None else 0.0
                        except ValueError:
                            cvss_score = 0.0  # Default if parsing fails

                        cve_id = str(id_elem.text)
                        cve_details = fetch_cve_description(cve_id)  # Fetch title and description
                        cve_exploitability = query_exploitdb_for_exploits(cve_id.replace("CVE-", "")) or cve_details["exploitability"] or kev.is_cve_known_exploited(cve_id)

                        vulnerabilities.append({
                            "ip": ip,
                            "port": portid,
                            "service": service_name,
                            "cve": cve_id,
                            "cvss": cvss_score,
                            "title": cve_details["title"],
                            "description": cve_details["description"],
                            "exploitability": cve_exploitability
                        })

    vulnerabilities.sort(key=lambda x: x["cvss"], reverse=True)
    return vulnerabilities

"""
Prettify the report we got so far for the end user!
While the LLM might only care about a CVE's description and ID to keep the ranking as fair as possible,
an human user that should be trusted with reviewing the LLM's output might care about some other fields like
the CVSS score or the exploitability given the availability of exploits on EDB at the current time.
"""
def export_full_report_to_csv(vulnerabilities, filename="vulnerabilities_full.csv"):
    headers = ["Rank", "CVE", "Description", "Port", "Service", "CVSS", "Exploitability"]

    with open(filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(headers)

        for i, vuln in enumerate(vulnerabilities, start=1):
            writer.writerow([i, vuln["cve"], vuln["description"], vuln["port"], vuln["service"], vuln["cvss"], vuln["exploitability"]])

    print(f"✅ Exported full report to {filename}")

def export_llm_input_to_csv(vulnerabilities, filename="vulnerabilities_llm.csv"):
    headers = ["CVE", "Description"]

    with open(filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(headers)

        for vuln in vulnerabilities:
            writer.writerow([vuln["cve"], vuln["description"]])

    print(f"✅ Exported CVE and Description only report to {filename}")

parser = argparse.ArgumentParser(description="Check CVE exploitability using searchsploit.")
parser.add_argument("-input", help="Path to the input CSV file")
args = parser.parse_args()
kev.download_cisa_json()
vulnerabilities = parse_nmap_output_xml(args.input)
export_full_report_to_csv(vulnerabilities)
export_llm_input_to_csv(vulnerabilities)
