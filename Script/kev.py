import json
import os
import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_FILENAME = "known_exploited_vulnerabilities.json"

"""Reads the catalogVersion from the locally stored JSON file."""
def get_local_catalog_version():
    if not os.path.exists(KEV_FILENAME):
        return None  # No local file exists

    try:
        with open(KEV_FILENAME, "r", encoding="utf-8") as file:
            data = json.load(file)
            return data.get("catalogVersion")
    except (json.JSONDecodeError, OSError) as e:
        print(f"Error reading local JSON: {e}")
        return None

"""Fetches the remote catalogVersion without downloading the entire file."""
def get_remote_catalog_version():
    try:
        response = requests.get(KEV_URL, timeout=10)  # Added timeout
        response.raise_for_status()  # Raise an error for bad responses (4xx, 5xx)
        data = response.json()
        return data.get("catalogVersion")
    except (requests.RequestException, json.JSONDecodeError) as e:
        print(f"Error fetching remote JSON: {e}")
        return None

"""Downloads the JSON file if the local version is outdated or missing."""
def download_cisa_json():
    local_version = get_local_catalog_version()
    remote_version = get_remote_catalog_version()

    if local_version == remote_version:
        print(f"Local file is up to date (Version: {local_version}). No download needed.")
        return

    print(f"Updating JSON file: {KEV_FILENAME} (Local: {local_version} → Remote: {remote_version})")

    try:
        response = requests.get(KEV_URL, timeout=20)
        response.raise_for_status()
        with open(KEV_FILENAME, "wb") as file:
            file.write(response.content)
        print(f"File downloaded successfully: {KEV_FILENAME}")
    except requests.RequestException as e:
        print(f"Failed to download the file: {e}")

"""Checks if the given CVE ID is in the known exploited vulnerabilities list."""
def is_cve_known_exploited(cve_id):
    if not os.path.exists(KEV_FILENAME):
        print(f"File {KEV_FILENAME} not found. Run `download_cisa_json()` first.")
        return False

    try:
        with open(KEV_FILENAME, "r", encoding="utf-8") as file:
            data = json.load(file)
            return any(vuln.get("cveID") == cve_id for vuln in data.get("vulnerabilities", []))
    except (json.JSONDecodeError, OSError) as e:
        print(f"Error loading JSON file: {e}")
        return False
