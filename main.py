#!/usr/bin/env python3

import requests
import json
import getpass
import argparse
import urllib3
import sys

# --- Configuration ---
# API Endpoints (Adjust if necessary for your NDFC version)
LOGIN_ENDPOINT = "/rest/logon"
# Common inventory endpoints: /api/v1/inventory/devices, /rest/inventory/all, /rest/inventory/lan-switches
INVENTORY_ENDPOINT = "/api/v1/inventory/devices"
# Header name used by NDFC for the token
TOKEN_HEADER = "Dcnm-Token"

# --- Disable SSL Warnings ---
# Required because NDFC often uses self-signed certificates
try:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print("[-] SSL warnings disabled.")
except AttributeError:
    print("[!] Could not disable SSL warnings. urllib3 version might be old.")
    # For older requests/urllib3:
    # requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def get_token(ndfc_ip, username, password):
    """Authenticates with NDFC and returns the session token."""
    login_url = f"https://{ndfc_ip}{LOGIN_ENDPOINT}"
    payload = {
        "userName": username,
        "userPassword": password
        # "domainId": "default" # Often not needed for TACACS/external auth unless multiple domains configured
    }
    headers = {
        'Content-Type': 'application/json'
    }

    print(f"[*] Attempting authentication to {login_url} as user '{username}'...")

    try:
        response = requests.post(
            login_url,
            headers=headers,
            json=payload,
            verify=False, # Ignore SSL certificate validation
            timeout=30     # Add a timeout
        )
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

        response_data = response.json()
        token = response_data.get(TOKEN_HEADER) # NDFC usually returns token in 'Dcnm-Token' field

        if not token:
            print("[!] Authentication successful, but token not found in response:")
            print(json.dumps(response_data, indent=2))
            return None

        print("[+] Authentication successful. Token obtained.")
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
            # Try to print the error message from NDFC if available
            error_details = e.response.json()
            print(f"    Error details: {error_details.get('message', 'No details provided.')}")
        except json.JSONDecodeError:
            print(f"    Response content: {e.response.text}")
        return None
    except json.JSONDecodeError:
        print("[!] Error: Failed to parse JSON response during authentication.")
        print(f"    Raw response: {response.text}")
        return None
    except Exception as e:
        print(f"[!] An unexpected error occurred during authentication: {e}")
        return None


def get_inventory(ndfc_ip, token):
    """Fetches the device inventory from NDFC using the provided token."""
    inventory_url = f"https://{ndfc_ip}{INVENTORY_ENDPOINT}"
    headers = {
        TOKEN_HEADER: token,
        'Content-Type': 'application/json'
    }

    print(f"[*] Fetching inventory from {inventory_url}...")

    try:
        response = requests.get(
            inventory_url,
            headers=headers,
            verify=False, # Ignore SSL certificate validation
            timeout=60     # Inventory calls can take longer
        )
        response.raise_for_status()

        inventory_data = response.json()
        print("[+] Inventory data received successfully.")
        return inventory_data

    except requests.exceptions.Timeout:
        print(f"[!] Error: Connection to {inventory_url} timed out.")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Error: Could not connect to NDFC at {ndfc_ip} for inventory.")
        print(f"    Details: {e}")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"[!] Failed to fetch inventory. Status Code: {e.response.status_code}")
        try:
            error_details = e.response.json()
            print(f"    Error details: {error_details.get('message', 'No details provided.')}")
        except json.JSONDecodeError:
            print(f"    Response content: {e.response.text}")
        # Check for specific 401 Unauthorized, which might mean token expired
        if e.response.status_code == 401:
            print("[!] Received 401 Unauthorized. Token might be invalid or expired.")
        return None
    except json.JSONDecodeError:
        print("[!] Error: Failed to parse JSON response for inventory.")
        print(f"    Raw response: {response.text}")
        return None
    except Exception as e:
        print(f"[!] An unexpected error occurred fetching inventory: {e}")
        return None

# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Connect to NDFC, authenticate via TACACS (user/pass), and dump inventory.")
    parser.add_argument("ndfc_ip", help="IP address or FQDN of the NDFC instance.")
    parser.add_argument("-u", "--username", help="TACACS username for NDFC login.", required=True)
    # Password will be prompted securely if not provided via an argument (not recommended)
    # parser.add_argument("-p", "--password", help="TACACS password (use prompt instead if possible)") # Avoid using this

    args = parser.parse_args()

    # Securely prompt for password
    ndfc_password = getpass.getpass(f"Enter password for user '{args.username}': ")

    if not ndfc_password:
        print("[!] Password cannot be empty.")
        sys.exit(1)

    # 1. Get Authentication Token
    auth_token = get_token(args.ndfc_ip, args.username, ndfc_password)

    if not auth_token:
        print("[!] Exiting due to authentication failure.")
        sys.exit(1)

    # 2. Get Inventory
    inventory = get_inventory(args.ndfc_ip, auth_token)

    # Optional: Logout (good practice, uncomment if needed)
    # print("[*] Logging out...")
    # logout_url = f"https://{args.ndfc_ip}/rest/logout"
    # try:
    #     requests.get(logout_url, headers={TOKEN_HEADER: auth_token}, verify=False, timeout=10)
    #     print("[+] Logout request sent.")
    # except Exception as e:
    #     print(f"[!] Error during logout: {e}")

    if not inventory:
        print("[!] Exiting due to failure fetching inventory.")
        sys.exit(1)

    # 3. Dump Inventory (Pretty Print JSON)
    print("\n" + "="*30 + " NDFC Inventory Dump " + "="*30)
    if isinstance(inventory, list) and not inventory:
        print("[!] Inventory is empty.")
    elif isinstance(inventory, list) or isinstance(inventory, dict):
         # Dump the raw JSON data received
         print(json.dumps(inventory, indent=2))
         print(f"\n[*] Found {len(inventory) if isinstance(inventory, list) else 'N/A'} devices/items in the raw dump.")
    else:
         print("[!] Unexpected inventory format received:")
         print(inventory)

    print("\n" + "="*79)
    print("[*] Script finished.")