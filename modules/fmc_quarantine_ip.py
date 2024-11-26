#!/usr/bin/env python3

import requests
import sys
import json
import time
import xml.etree.ElementTree as ET
from datetime import datetime

# Parameters
ip_address = sys.argv[2]  # IP Address passed as argument
instance_conf_file = 'instance.conf'  # Your instance.conf file

# Disable SSL warnings (not recommended for production)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def read_instance_config(file_path):
    """
    Reads and parses the XML file at the given path.
    Extracts relevant values (fmc_ip, fmc_user, fmc_password, fmc_dyn_object_name) from the config section.
    Returns the parsed XML tree, root element, and the extracted values.
    """
    try:
        # Parse the XML file
        tree = ET.parse(file_path)
        root = tree.getroot()

        # Extract values from the <config> section
        config = root.find(".//config")
        if config is None:
            raise ValueError("<config> section not found in the XML file.")

        # Extract values for fmc_ip, fmc_user, fmc_password, and fmc_dyn_object_name
        fmc_ip = config.find(".//ipaddress[@name='fmc_ip']").text if config.find(".//ipaddress[@name='fmc_ip']") is not None else None
        fmc_user = config.find(".//string[@name='fmc_user']").text if config.find(".//string[@name='fmc_user']") is not None else None
        fmc_password = config.find(".//string[@name='fmc_password']").text if config.find(".//string[@name='fmc_password']") is not None else None
        fmc_dyn_object_name = config.find(".//string[@name='fmc_dyn_object_name']").text if config.find(".//string[@name='fmc_dyn_object_name']") is not None else None
        quarantine_time = config.find(".//string[@name='quarantine_time']").text if config.find(".//string[@name='quarantine_time']") is not None else None

        # Return the tree, root, and extracted values
        return fmc_ip, fmc_user, fmc_password, fmc_dyn_object_name, quarantine_time, tree, root

    except ET.ParseError as e:
        print(f"Error parsing XML file {file_path}: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        sys.exit(1)

def indent_tree(elem, level=0):
    """
    Indents the XML tree to make it more human-readable.
    """
    i = "\n" + level * "  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        for child in elem:
            indent_tree(child, level + 1)
        if not child.tail or not child.tail.strip():
            child.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i

def update_instance_config(file_path, auth_token, domain_uuid, timestamp):
    """
    Updates the instance.conf file with new auth_token, domain_uuid, and timestamp.
    Adds or updates values inside the <config> section.
    """
    try:
        # Read and parse the XML file
        _, _, _, _, _, tree, root = read_instance_config(file_path)

        # Locate the <config> section
        config = root.find(".//config")
        if config is None:
            raise ValueError("<config> section not found. Cannot update values.")

        # Update or create <string name="auth_token"> element
        update_or_create_string_element(config, "auth_token", auth_token)

        # Update or create <string name="domain_uuid"> element
        update_or_create_string_element(config, "domain_uuid", domain_uuid)

        # Update or create <string name="last_updated"> element
        update_or_create_string_element(config, "last_updated", timestamp)

        # Add pretty-print indentation to the XML structure
        indent_tree(root)

        # Write the modified XML back to the file
        tree.write(file_path, encoding="utf-8", xml_declaration=True)
        print(f"Successfully updated {file_path} with auth_token, domain_uuid, and timestamp.")

    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

def update_or_create_string_element(config, name, value):
    """
    Helper function that either updates the value of an existing <string name="..."> element,
    or creates a new one if it doesn't exist.
    """
    # Find the string element by its 'name' attribute
    element = config.find(f".//string[@name='{name}']")
    
    # If the element does not exist, create it
    if element is None:
        element = ET.SubElement(config, "string", name=name)
    
    # Update or set the text content of the element
    element.text = value
    

# Function to get the authentication token and domain UUID
def get_auth_token_and_domain_uuid(server, user, password):
    print("\nGenerating Token and Connecting\n")
    
    # Ensure the URL has the scheme (http:// or https://)
    if not server.startswith("http://") and not server.startswith("https://"):
        server = "https://" + server  # Or use https:// if needed
    
    api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
    auth_url = server + api_auth_path
    headers = {'Content-Type': 'application/json'}

    try:
        # Send POST request to get the authentication token
        r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user, password), verify=False)

        # Print raw response for debugging and troubleshooting
#        print(f"Response Status Code: {r.status_code}")
#        print(f"Response Headers: {r.headers}")
#        print(f"Response Text: {r.text}")

        # Extract the authentication token from headers
        auth_token = r.headers.get('X-auth-access-token', default=None)
        if not auth_token:
            print("auth_token not found in response headers. Exiting...")
            sys.exit()

        # Extract domain UUID from headers
        domain_uuid = r.headers.get('DOMAIN_UUID', default=None)
        if not domain_uuid:
            print("domain_uuid not found in response headers. Exiting...")
            sys.exit()

        print(f"\nToken: {auth_token}")
        print(f"Domain UUID: {domain_uuid}")

        return auth_token, domain_uuid

    except json.JSONDecodeError as err:
        print(f"Error in generating auth token --> Unable to parse JSON: {err}")
        sys.exit()
    except Exception as err:
        print(f"Error in generating auth token --> {err}")
        sys.exit()


# Function to get dynamic object ID
def get_dynamic_object_id(auth_token, domain_uuid):
    print("\nFetching Dynamic Object ID...\n")
    headers = {
        'Content-Type': 'application/json',
        'X-auth-access-token': auth_token
    }
    api_url = f"/api/fmc_config/v1/domain/{domain_uuid}/search/object?filter={dynamic_object_name}"
    auth_url = "https://" + server + api_url

    try:
        # Sending GET request to fetch dynamic object ID
        r = requests.get(auth_url, headers=headers, verify=False)
        
        if r.status_code != 200:
            print(f"Error fetching dynamic object: {r.text}")
            sys.exit()
        
        response_json = r.json()
        
        if 'items' in response_json and len(response_json['items']) > 0:
            dynamic_object_id = response_json['items'][0]['id']
            print(f"Dynamic Object ID: {dynamic_object_id}")
            return dynamic_object_id
        else:
            print("Dynamic object not found.")
            sys.exit()

    except Exception as err:
        print(f"Error in fetching dynamic object ID --> {err}")
        sys.exit()

# Function to update the dynamic object with the IP address
def update_dynamic_object(auth_token, dynamic_object_id, domain_uuid):
    print(f"\nUpdating Dynamic Object with IP: {ip_address}...\n")
    
    headers = {
        'Content-Type': 'application/json',
        'X-auth-access-token': auth_token
    }

    api_url = f"/api/fmc_config/v1/domain/{domain_uuid}/object/dynamicobjectmappings"
    auth_url = "https://" + server + api_url

    body = {
        "add": [
            {
                "dynamicObject": {
                    "id": dynamic_object_id
                },
                "mappings": [
                    ip_address
                ]
            }
        ]
    }

    try:
        r = requests.post(auth_url, headers=headers, json=body, verify=False)

        if r.status_code == 201:
            print(f"Successfully added IP address {ip_address} to dynamic object.")
        else:
            print(f"Error in updating dynamic object: {r.text}")
            sys.exit()

    except Exception as err:
        print(f"Error in updating dynamic object --> {err}")
        sys.exit()

# Function to wait for a specified time
def wait_for_seconds(seconds):
    print(f"\nWaiting for {seconds} seconds...\n")
    time.sleep(seconds)

# Function to remove an IP address from the dynamic object
def remove_ip_from_dynamic_object(auth_token, dynamic_object_id, domain_uuid):
    print(f"\nRemoving IP: {ip_address} from Dynamic Object...\n")
    
    headers = {
        'Content-Type': 'application/json',
        'X-auth-access-token': auth_token
    }

    api_url = f"/api/fmc_config/v1/domain/{domain_uuid}/object/dynamicobjectmappings"
    auth_url = "https://" + server + api_url

    body = {
        "remove": [
            {
                "dynamicObject": {
                    "id": dynamic_object_id
                },
                "mappings": [
                    ip_address
                ]
            }
        ]
    }

    try:
        r = requests.post(auth_url, headers=headers, json=body, verify=False)

        if r.status_code == 201:
            print(f"Successfully removed IP address {ip_address} from dynamic object.")
        else:
            print(f"Error in removing IP address from dynamic object: {r.text}")
            sys.exit()

    except Exception as err:
        print(f"Error in removing IP address from dynamic object --> {err}")
        sys.exit()

# Main logic
if __name__ == "__main__":
    reuse_token = False

    fmc_ip, fmc_user, fmc_password, fmc_dyn_object_name, quarantine_time, tree, root = read_instance_config(instance_conf_file)

    # Now use the extracted variables
    server = fmc_ip
    user = fmc_user
    password = fmc_password
    dynamic_object_name = fmc_dyn_object_name

    # Print values to confirm or troubleshooting
#    print(f"Server: {server}")
#    print(f"User: {user}")
#    print(f"Password: {password}")
#    print(f"Dynamic Object Name: {dynamic_object_name}")

    config = root.find("./config")

    if config is not None:
        last_updated_elem = config.find("./string[@name='last_updated']")
        auth_token_elem = config.find("./string[@name='auth_token']")
        domain_uuid_elem = config.find("./string[@name='domain_uuid']")
        quarantine_time_elem = config.find("./string[@name='quarantine_time']")

        if last_updated_elem is not None and auth_token_elem is not None and domain_uuid_elem is not None:
            last_updated = last_updated_elem.text
            auth_token = auth_token_elem.text
            domain_uuid = domain_uuid_elem.text
            quarantine_time = int(quarantine_time_elem.text) if quarantine_time_elem is not None else 60

            last_updated_time = time.mktime(time.strptime(last_updated, '%Y-%m-%d %H:%M:%S'))
            current_time = time.time()

            if current_time - last_updated_time < 1200:  # 20 minutes
                print("Using existing token from instance.conf.")
                reuse_token = True
        else:
            print("No valid token in instance.conf. Generating new token...")

    if not reuse_token:
        
        auth_token, domain_uuid = get_auth_token_and_domain_uuid(server, user, password)
        

        # Update the instance.conf with new values
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        update_instance_config(instance_conf_file, auth_token, domain_uuid, timestamp)

    # Proceed with other actions using auth_token and domain_uuid - for troubleshooting purposes
#    print(f"Token: {auth_token}")
#    print(f"Domain UUID: {domain_uuid}")

    # Fetch dynamic object ID
    dynamic_object_id = get_dynamic_object_id(auth_token, domain_uuid)

    # Update the dynamic object with the IP address
    update_dynamic_object(auth_token, dynamic_object_id, domain_uuid)

    # Wait for the specified quarantine time
    wait_for_seconds(quarantine_time)

    # Remove the IP address from the dynamic object
    remove_ip_from_dynamic_object(auth_token, dynamic_object_id, domain_uuid)
