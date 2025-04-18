#!/usr/bin/env python3

import requests
import json
import getpass
import argparse
import urllib3
import sys
import csv
import os

# --- Configuration ---
# API Endpoints
LOGIN_ENDPOINT = "/login"
FABRICS_ENDPOINT = "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics"
INVENTORY_ENDPOINT_TEMPLATE = "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/{fabricName}/inventory/switchesByFabric"

# Authentication Domain
AUTH_DOMAIN = "TACACS-legacy"

# Output CSV Filename
DEFAULT_CSV_FILENAME = "ndfc_fabric_inventory.csv"

# --- Disable SSL Warnings ---
try:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print("[-] SSL warnings disabled.")
except AttributeError:
    print("[!] Could not disable SSL warnings. urllib3 version might be old.")

def get_token(ndfc_ip, username, password, domain):
    """Authenticates with NDFC using specified domain and returns the JWT token."""
    login_url = f"https://{ndfc_ip}{LOGIN_ENDPOINT}"
    payload = {
        "domain": domain,
        "userName": username,
        "userPasswd": password
    }
    headers = {'Content-Type': 'application/json'}

    print(f"[*] Attempting authentication to {login_url} as user '{username}' in domain '{domain}'...")
    try:
        response = requests.post(login_url, headers=headers, json=payload, verify=False, timeout=30)
        response.raise_for_status()
        response_data = response.json()
        token = response_data.get("jwttoken")
        if not token:
            print("[!] Authentication successful, but 'jwttoken' not found in response:")
            print(json.dumps(response_data, indent=2))
            return None
        print("[+] Authentication successful. JWT Token obtained.")
        return token
    except requests.exceptions.Timeout:
        print(f"[!] Error: Connection to {login_url} timed out.")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Error: Could not connect to NDFC at {ndfc_ip}. Check IP/port and connectivity.")
        print(f"    Details: {e}")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"[!] Authentication failed. Status Code: {e.response.status_code}")
        try:
            error_details = e.response.json()
            print(f"    Error details: {error_details.get('message', json.dumps(error_details))}")
        except json.JSONDecodeError:
            print(f"    Response content: {e.response.text}")
        return None
    except Exception as e:
        print(f"[!] An unexpected error occurred during authentication: {e}")
        return None

def get_fabrics(ndfc_ip, token):
    """Fetches the list of fabrics from NDFC."""
    fabrics_url = f"https://{ndfc_ip}{FABRICS_ENDPOINT}"
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

    print(f"[*] Fetching fabrics from {fabrics_url}...")
    try:
        response = requests.get(fabrics_url, headers=headers, verify=False, timeout=45)
        response.raise_for_status()
        fabrics_data = response.json()
        # Check if response is a list
        if isinstance(fabrics_data, list):
             # Check if list is empty or if items are dicts with 'fabricName'
             if not fabrics_data:
                 print("[+] No fabrics found.")
                 return [] # Return empty list
             # Validate first item structure (optional but good practice)
             if isinstance(fabrics_data[0], dict) and 'fabricName' in fabrics_data[0]:
                 print(f"[+] Found {len(fabrics_data)} fabrics.")
                 return fabrics_data # Return the full list of dicts
             else:
                 print("[!] Fabric list format unexpected. Expected list of dictionaries with 'fabricName'.")
                 print(json.dumps(fabrics_data, indent=2))
                 return None
        else:
            print("[!] Unexpected format received for fabrics list (expected a JSON list):")
            print(json.dumps(fabrics_data, indent=2))
            return None

    except requests.exceptions.Timeout:
        print(f"[!] Error: Connection to {fabrics_url} timed out.")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Error: Could not connect to NDFC at {ndfc_ip} for fabrics.")
        print(f"    Details: {e}")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"[!] Failed to fetch fabrics. Status Code: {e.response.status_code}")
        try:
            error_details = e.response.json()
            print(f"    Error details: {error_details.get('message', json.dumps(error_details))}")
        except json.JSONDecodeError:
            print(f"    Response content: {e.response.text}")
        if e.response.status_code == 401: print("[!] Received 401 Unauthorized. Token might be invalid or expired.")
        return None
    except Exception as e:
        print(f"[!] An unexpected error occurred fetching fabrics: {e}")
        return None

def select_fabric(fabrics_list):
    """Prompts the user to select a fabric from the list by its 'fabricName'."""
    if not fabrics_list:
        print("[!] No fabrics available to select.")
        return None

    print("\nAvailable Fabrics:")
    valid_fabrics = []
    for i, fabric in enumerate(fabrics_list):
        # Use 'fabricName' key as specified
        fabric_name = fabric.get('fabricName')
        if fabric_name:
            print(f"  {len(valid_fabrics) + 1}: {fabric_name}")
            valid_fabrics.append(fabric_name) # Store only the name
        else:
            print(f"[!] Warning: Fabric entry at index {i} missing 'fabricName'. Skipping.")

    if not valid_fabrics:
        print("[!] No fabrics with valid names found.")
        return None

    while True:
        try:
            choice = input(f"Select fabric number (1-{len(valid_fabrics)}): ")
            choice_index = int(choice) - 1
            if 0 <= choice_index < len(valid_fabrics):
                selected_fabric_name = valid_fabrics[choice_index]
                print(f"[*] You selected: {selected_fabric_name}")
                return selected_fabric_name
            else:
                print("[!] Invalid choice. Please enter a number from the list.")
        except ValueError:
            print("[!] Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\n[!] Operation cancelled by user.")
            return None

def get_fabric_inventory(ndfc_ip, token, fabric_name):
    """Fetches the device inventory for a specific fabric."""
    # URL Encode the fabric name in case it contains special characters
    import urllib.parse
    encoded_fabric_name = urllib.parse.quote(fabric_name)
    inventory_url = f"https://{ndfc_ip}{INVENTORY_ENDPOINT_TEMPLATE.format(fabricName=encoded_fabric_name)}"
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

    print(f"[*] Fetching inventory for fabric '{fabric_name}' from {inventory_url}...")
    try:
        response = requests.get(inventory_url, headers=headers, verify=False, timeout=90)
        response.raise_for_status()
        inventory_data = response.json()
        # Expecting a list of switch dictionaries
        if isinstance(inventory_data, list):
            print(f"[+] Inventory data received successfully ({len(inventory_data)} devices).")
            return inventory_data
        else:
            print("[!] Unexpected format received for inventory list (expected a JSON list):")
            print(json.dumps(inventory_data, indent=2))
            return None

    except requests.exceptions.Timeout:
        print(f"[!] Error: Connection to {inventory_url} timed out.")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Error: Could not connect to NDFC at {ndfc_ip} for inventory.")
        print(f"    Details: {e}")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"[!] Failed to fetch inventory for fabric '{fabric_name}'. Status Code: {e.response.status_code}")
        try:
            error_details = e.response.json()
            print(f"    Error details: {error_details.get('message', json.dumps(error_details))}")
        except json.JSONDecodeError:
            print(f"    Response content: {e.response.text}")
        if e.response.status_code == 401: print("[!] Received 401 Unauthorized. Token might be invalid or expired.")
        elif e.response.status_code == 404: print(f"[!] Received 404 Not Found. Check if fabric name '{fabric_name}' is correct and API endpoint is valid.")
        return None
    except Exception as e:
        print(f"[!] An unexpected error occurred fetching inventory: {e}")
        return None

def write_inventory_to_csv(inventory_data, filename):
    """Parses inventory data and writes logicalName, model, serialNumber to a CSV file."""
    if not inventory_data:
        print("[!] No inventory data to write to CSV.")
        return False

    # Use the specified keys from the user
    key_hostname = 'logicalName'   # Changed from hostName
    key_model = 'model'            # Already correct
    key_serial = 'serialNumber'    # Already correct

    # Define CSV headers (can be different from JSON keys if desired)
    headers = ['hostname', 'model', 'serial'] # Keep CSV headers user-friendly
    missing_keys_warning = False

    print(f"[*] Writing inventory to CSV file: {filename}")
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()

            for i, switch in enumerate(inventory_data):
                # Ensure switch is a dictionary before trying to get keys
                if not isinstance(switch, dict):
                    print(f"[!] Warning: Inventory item at index {i} is not a dictionary. Skipping. Data: {switch}")
                    continue

                # Use .get() to safely retrieve values, providing 'N/A' if key missing
                hostname = switch.get(key_hostname, 'N/A')
                model = switch.get(key_model, 'N/A')
                serial = switch.get(key_serial, 'N/A')

                # Simple check and warning for missing data (optional, but helpful)
                if (hostname == 'N/A' or model == 'N/A' or serial == 'N/A') and not missing_keys_warning:
                     print(f"[!] Warning: Found 'N/A' for some devices. Ensure keys '{key_hostname}', '{key_model}', '{key_serial}' are correct in the API response for all devices.")
                     # Print the first problematic device structure for debugging
                     print(f"    Example device data with N/A: {switch}")
                     missing_keys_warning = True # Show warning only once

                writer.writerow({
                    headers[0]: hostname, # Map logicalName to 'hostname' header
                    headers[1]: model,
                    headers[2]: serial
                })
        print(f"[+] Successfully wrote {len(inventory_data)} devices to {filename}")
        return True
    except IOError as e:
        print(f"[!] Error writing to CSV file {filename}: {e}")
        return False
    except Exception as e:
        print(f"[!] An unexpected error occurred during CSV writing: {e}")
        return False

# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Connect to NDFC, authenticate, select a fabric, and dump its inventory to CSV.")
    parser.add_argument("ndfc_ip", help="IP address or FQDN of the NDFC instance.")
    parser.add_argument("-u", "--username", help="TACACS username for NDFC login.", required=True)
    parser.add_argument("-d", "--domain", help=f"Authentication domain (default: {AUTH_DOMAIN})", default=AUTH_DOMAIN)
    parser.add_argument("-o", "--outfile", help=f"Output CSV filename (default: {DEFAULT_CSV_FILENAME})", default=DEFAULT_CSV_FILENAME)

    args = parser.parse_args()

    ndfc_password = getpass.getpass(f"Enter password for user '{args.username}' in domain '{args.domain}': ")
    if not ndfc_password:
        print("[!] Password cannot be empty.")
        sys.exit(1)

    # 1. Get Token
    auth_token = get_token(args.ndfc_ip, args.username, ndfc_password, args.domain)
    if not auth_token: sys.exit(1)

    # 2. Get Fabrics
    fabrics = get_fabrics(args.ndfc_ip, auth_token)
    if fabrics is None: sys.exit(1) # API call failed
    if not fabrics: # Empty list is success, but no fabrics to choose from
        print("[*] No fabrics found on the NDFC instance.")
        sys.exit(0)

    # 3. Select Fabric
    selected_fabric = select_fabric(fabrics)
    if not selected_fabric: sys.exit(1) # User cancelled or no valid fabrics

    # 4. Get Inventory
    inventory = get_fabric_inventory(args.ndfc_ip, auth_token, selected_fabric)
    if inventory is None: sys.exit(1) # API call failed
    if not inventory: # Empty list is success, but no devices in fabric
        print(f"[!] Inventory for fabric '{selected_fabric}' is empty.")
        # Optionally create an empty CSV
        # success = write_inventory_to_csv([], args.outfile)
        sys.exit(0)

    # 5. Write CSV
    success = write_inventory_to_csv(inventory, args.outfile)

    print("\n[*] Script finished.")
    sys.exit(0 if success else 1)