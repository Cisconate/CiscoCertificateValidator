import paramiko
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import requests
from OpenSSL.crypto import X509Store
from bs4 import BeautifulSoup
from OpenSSL import crypto
import os
import csv
import re
import pollsnmp

test_cert = '''-----BEGIN CERTIFICATE-----
MIIDeTCCAmGgAwIBAgIEAm7O9TANBgkqhkiG9w0BAQsFADAnMQ4wDAYDVQQKEwVD
aXNjbzEVMBMGA1UEAxMMQUNUMiBTVURJIENBMB4XDTE4MDQwNzExNTIxN1oXDTI5
MDUxNDIwMjU0MVowZTElMCMGA1UEBRMcUElEOkM5MzAwLTQ4UCBTTjpGQ1cyMjE0
RzBRRTEOMAwGA1UEChMFQ2lzY28xGDAWBgNVBAsTD0FDVC0yIExpdGUgU1VESTES
MBAGA1UEAxMJQzkzMDAtNDhQMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEA484aW4tvZnK/hnTPB64agl3V42vVo00W4div4cRFhWHuDVGmujwcG1yTQX95
suZ2SCiCst7bxkRVp6/4X0j337aSYsZ+RONFLELIky5Zg0N0o7IqPsfjJPXL+nN9
2LON4t5jvUkvm+S0urTjWnrcvfIhfbyOoOoJbH96P6RncyhSweXe1yVdN0LlVD7V
+iUBIp7Kz0jswJ8V+7n9G9i5tWq3KBgZmFGlXYxn60zf5AZ3IuV1wFH8OujhFpdw
mbogxKsSE0CgcDIkz+aiTu9V1Gws7PqpP+Jk5wG6KgufAaY3ofcVDv3+2kal0/2m
WTnrPdxLvvDnwdqClOyWnnj0kQIDAQABo28wbTAOBgNVHQ8BAf8EBAMCBeAwDAYD
VR0TAQH/BAIwADBNBgNVHREERjBEoEIGCSsGAQQBCRUCA6A1EzNDaGlwSUQ9VVlK
UVEwWkhCUUNHVkdoMUlFNXZkaUF6TUNBeE9EbzBPVG94TmlBZ2ZoYz0wDQYJKoZI
hvcNAQELBQADggEBALnc82sw85m5UJJeRaGpoLX0qgDAOQOsSyK0j/lCYPSM8pCn
tiJwyazMeO6H8Q5FvvW1tT/mrSFZ0Q+0oXbpiDXiK0BbkKYaugpKBKExxMdmLLF4
jMTivi1BS858yaezTw4XjroiZBkKlTveaKU+TvbwgQ4V1XnytlJKPKa0W6G3cjBD
hoVqjKFBvLmAwHn+gEMePRG8Gul0unuMah/yp0Jyt/pz+8sSDLJV49XKkUxRaxgJ
NlrVagTKfTFNZBE+DCCroSnM6euZgxpSZRRKXGMZxwJkxcy8hlI5qpalPFbxPeF5
GCODUHGQrsxbqfFM1j6Dd+O9EvXQlHY7youznsM=
-----END CERTIFICATE-----
'''

page_url = 'https://www.cisco.com/security/pki/'
urls = []
trusted_cert_directory = "trusted_certs"
trust_store = X509Store
csv_file_path = "testinventory.csv"
oid_group = [".1.3.6.1.4.1.9.9.25.1.1.1.2.7", #IOSXE/ISR
             ".1.3.6.1.2.1.1.1.0"]   #ASA/FTD

community = "FedSecLab"
# Sample data: list of server information
test_servers = [
    {"IP Address": "192.168.30.1", "username": "nstapp", "password": "Cisco1234%67", "Software": "IOS-XE"},
    {"IP Address": "192.168.30.2", "username": "nstapp", "password": "Cisco1234%67", "Software": "IOS-XE"},
    {"IP Address": "192.168.30.3", "username": "nstapp", "password": "Cisco1234%67", "Software": "ASA"},
    {"IP Address": "192.168.30.74", "username": "nstapp", "password": "Cisco1234%67", "Software": "IOS-XE"}
]

# Lock for thread-safe print statements
print_lock = threading.Lock()

def import_inventory(csvfilepath):
    # Get the absolute path based on the current script's directory
    file_path = os.path.join(os.path.dirname(__file__), csvfilepath)

    # Initialize an empty list to store rows
    data = []

    # Open the CSV file and read its contents
    try:
        with open(file_path, mode="r", newline='') as file:
            csv_reader = csv.DictReader(file)
            data = [row for row in csv_reader]

    except FileNotFoundError:
        print(f"The file at {file_path} was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

    return data


def verify_sn_pid(connection, new_hostname):
    """
    Pulls trusted pki info, parses for SN and PID, then compares to sh version output

    This method uses "Invoke Shell" as there appears to be a bug with client.command_exec()
    with Cisco devices.  Only one command can be sent before the client disconnects with command_exec().

    Parameters:
    - new_client (ssh connection): A dictionary containing server connection details.
    - new_hostname (hostname): A string containing server hostname.
    """
    try:

        # Allow the shell to initialize (may need to wait a moment for prompt)
        time.sleep(2)

        # Send Command
        connection.send("show crypto pki certificate verbose | i serialNumber=PID:\n")
        time.sleep(2)  # Allow some time for the command to execute

        # Read the output after sending the command
        output = connection.recv(1024).decode('utf-8')  # Adjust buffer size as needed

        # Ensure multiple lines of output are curated to one copy
        first_line = output.split('\r')[1]

        # Remove duplicate lines
        text_output = first_line.split(" SN:")

        # Curate SN and PID
        sudi_device_sn = text_output[-1]
        sudi_device_pid = text_output[0].split("PID:")[1]

        # Send Command
        connection.send("show license udi\n")
        time.sleep(2)  # Allow some time for the command to execute

        # Read the output after sending the command
        output = connection.recv(1024).decode('utf-8')  # Adjust buffer size as needed

        # Separate each line for easy parsing
        lines = output.split('\r')

        # Curate "show license udi" SN, and PID
        license_device_pid = lines[1].split(',SN:')[0].split('PID:')[1]
        license_device_sn = lines[1].split(',SN:')[1]

        # Thread-safe print output
        with print_lock:
            if license_device_sn == sudi_device_sn and license_device_pid == sudi_device_pid:
                print(
                    f"Output from {new_hostname}: Serial {sudi_device_sn} and PID {sudi_device_pid} from {new_hostname} PASSED Validation")
            else:
                print(
                    f"Output from {new_hostname}: Serial {license_device_pid} and PID {license_device_sn} from {new_hostname} FAILED Validation")

    except Exception as e:
        with print_lock:
            print(f"Failed to connect to {new_hostname}: {e}")


def collect_cert(connection, new_hostname):
    """
    Pulls Certificate information from device "show platform..." output of cisco device

    This method uses "Invoke Shell" as there appears to be a bug with client.command_exec()
    with Cisco devices.  Only one command can be sent before the client disconnects with command_exec().

    Parameters:
    - connection (ssh connection): A dictionary containing server connection details.
    - new_hostname (hostname): A string containing server hostname.
    """
    try:
        # Allow the shell to initialize (may need to wait a moment for prompt)
        time.sleep(2)

        # Send Command
        connection.send("show platform sudi certificate sign nonce 123\n")
        time.sleep(4)  # Allow some time for the command to execute

        # Read the output after sending the command
        output = connection.recv(200000).decode('utf-8')  # Adjust buffer size as needed

        # Ensure multiple lines of output are curated to one copy
        first_line = output.split('-----END CERTIFICATE-----\r')[2]

        # Test final concat
        result = first_line + '-----END CERTIFICATE-----'

    except Exception as e:
        with print_lock:
            print(f"Failed to connect to {new_hostname}: {e}")

    return result


def validate_certificate_live(cert_to_verify_data, store):
    """
    Validate a certificate against the trust store.

    Parameters:
    - cert_to_verify_data (bytes): PEM-encoded certificate to validate.
    - store (X509Store): X509Store containing trusted certificates.

    Returns:
    - bool: True if the certificate is valid, False otherwise.
    """
    try:
        # Load the certificate to be validated
        cert_to_verify = crypto.load_certificate(crypto.FILETYPE_PEM, cert_to_verify_data)

        # Create an X509StoreContext with the store and the certificate to verify
        store_ctx = crypto.X509StoreContext(store, cert_to_verify)
        store_ctx.verify_certificate()
        print("Certificate validation successful.")
        return True
    except crypto.X509StoreContextError as e:
        print(f"Certificate validation failed: {e}")
        return False


def download_certificate(url, output_file):
    """
    Download a .cer certificate from the specified URL and save it as a binary file.

    Parameters:
    - url (str): The URL to the .cer certificate file.
    - output_file (str): The path where the binary file will be saved.
    """
    filepath = os.path.join(trusted_cert_directory,  output_file)
    try:
        # Send a GET request to the URL
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for bad responses (4xx or 5xx)

        # Write the content to a binary file
        with open(filepath, "wb") as file:
            file.write(response.content)

        print(f"Downloaded and saved the certificate to {filepath}")

    except requests.RequestException as e:
        print(f"Error downloading certificate from {url}: {e}")


def extract_urls_from_page_and_download(url):
    """
    Extract all URLs from the links in the specified HTML page, and download relevant certificates.

    Parameters:
    - url (str): The URL of the page to scrape.

    Returns:
    - list: A list of extracted URLs.
    """
    try:
        # Fetch the content of the page
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for bad responses (4xx or 5xx)

        # Parse the page content with BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')

        # Find all anchor tags and extract their href attributes
        links = soup.find_all('a')
        for link in links:
            if link.get('href') and 'PEM' in link.text:
                download_certificate(link.get('href'), link.text)
        return

    except requests.RequestException as e:
        print(f"Error fetching page {url}: {e}")
        return


def create_trust_store_from_directory(directory_path):
    """
    Create an X509Store trust store from all certificate files in a specified directory.

    Parameters:
    - directory_path (str): The path to the directory containing PEM-encoded certificate files.

    Returns:
    - X509Store: The created trust store with all certificates loaded.
    """
    store = crypto.X509Store()

    # Iterate over all files in the directory
    for filename in os.listdir(directory_path):
        # Only consider files with a .pem or .cer extension
        if filename.endswith("- PEM") or filename.endswith("- CER"):
            cert_path = os.path.join(directory_path, filename)
            try:
                # Load the certificate file
                with open(cert_path, "rb") as cert_file:
                    cert_data = cert_file.read()

                    # Load the certificate from the PEM data
                    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

                    # Add the certificate to the trust store
                    store.add_cert(certificate)
                    print(f"Added certificate from {filename} to the trust store.")
            except Exception as e:
                print(f"Error adding certificate from {filename} to store: {e}")

    return store


def ssh_connect_and_execute(server):
    """
    Connects to a server over SSH and executes a command using invoke_shell.

    Parameters:
    - server (dict): A dictionary containing server connection details.
    """
    hostname = server["IP Address"]
    username = "nstapp"
    password = "Cisco1234%67"
    software = server["Software"]

    try:
        # Initialize SSH client
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the server
        if software == "IOSXE":
            client.connect(hostname=hostname, username=username, password=password, look_for_keys=False)
            with print_lock:
                print(f"started {hostname}")
            shell = client.invoke_shell()
            # Thread-safe print output
            with print_lock:
                print(f"Connected to {hostname}")

            # Collect certificate from device for validation
            cert = collect_cert(shell, hostname)

            # Validate certificate trust path
            validate_certificate_live(cert, trust_store)

            # Verify certificate details match device details
            verify_sn_pid(shell, hostname)


    except Exception as e:
        with print_lock:
            print(f"Failed to connect (MAIN) to {hostname}: {e}")

    finally:
        client.close()


# def ios_xe_verify_sn_pid2(new_client, new_hostname):
#     """
#     Pulls trusted pki info, parses for SN and PID, then compares to sh version output
#
#     Parameters:
#     - new_client (ssh connection): A dictionary containing server connection details.
#     - new_hostname (hostname): A string containing server hostname.
#     """
#     try:
#         # Set terminal length
#         # stdin, stdout, stderr = new_client.exec_command("terminal length 0")
#         # output = stdout.read().decode().strip()
#
#         # List all PID/SN (there can be multiple) and check for a match
#         stdin, stdout, stderr = new_client.exec_command("show crypto pki certificate verbose | i serialNumber=PID:")
#         output = stdout.read().decode().strip()
#
#         # Ensure multiple lines of output are curated to one copy
#         first_line = output.split('\r', 1)[0]
#         text_output = first_line.split(" SN:")
#
#         # Curate SN and PID
#         sudi_device_sn = text_output[-1]
#         sudi_device_pid = text_output[0].split("PID:")[1]
#
#         # Thread-safe print output
#         with print_lock:
#             print(f"Output from {new_hostname}: SUDI Device SN - {sudi_device_sn}")
#             print(f"Output from {new_hostname}: SUDI Device PID - {sudi_device_pid}")
#
#         # List all PID/SN (there can be multiple) and check for a match
#         stdin, stdout, stderr = new_client.exec_command("show version | beg Model Number")
#         output = stdout.read().decode().strip()
#
#         # Separate each line for easy parsing
#         lines = output.split('\r')
#
#         # Curate "Show version" SN, and PID
#         vers_device_PID = lines[0].split(': ')[1]
#         vers_device_SN = lines[1].split(': ')[1]
#
#         # Thread-safe print output
#         with print_lock:
#             print(f"Output from {new_hostname}: Vers Device SN - {vers_device_SN}")
#             print(f"Output from {new_hostname}: Vers Device PID - {vers_device_PID}")
#
#     except Exception as e2:
#         with print_lock:
#             print(f"Failed to connect (IOS-XE) to {new_hostname}: {e2}")
#
#
# def ios_xe_verify_sn_pid(new_client, new_hostname):
#     """
#     Pulls trusted pki info, parses for SN and PID, then compares to sh version output
#
#     This method uses "Invoke Shell" as there appears to be a bug with client.command_exec()
#     with Cisco devices.  Only one command can be sent before the client disconnects with command_exec().
#
#     Parameters:
#     - new_client (ssh connection): A dictionary containing server connection details.
#     - new_hostname (hostname): A string containing server hostname.
#     """
#     try:
#         # Invoke a shell session
#         shell = new_client.invoke_shell()
#
#         # Allow the shell to initialize (may need to wait a moment for prompt)
#         time.sleep(2)
#
#         # Send Command
#         shell.send("show crypto pki certificate verbose | i serialNumber=PID:\n")
#         time.sleep(2)  # Allow some time for the command to execute
#
#         # Read the output after sending the command
#         output = shell.recv(1024).decode('utf-8')  # Adjust buffer size as needed
#
#         # Ensure multiple lines of output are curated to one copy
#         first_line = output.split('\r')[2]
#
#         # Remove duplicate lines
#         text_output = first_line.split(" SN:")
#
#         # Curate SN and PID
#         sudi_device_sn = text_output[-1]
#         sudi_device_pid = text_output[0].split("PID:")[1]
#
#         # Send Command
#         shell.send("show version | beg Model Number\n")
#         time.sleep(2)  # Allow some time for the command to execute
#
#         # Read the output after sending the command
#         output = shell.recv(1024).decode('utf-8')  # Adjust buffer size as needed
#
#         # Separate each line for easy parsing
#         lines = output.split('\r')
#
#         # Curate "Show version" SN, and PID
#         vers_device_PID = lines[1].split(': ')[1]
#         vers_device_SN = lines[2].split(': ')[1]
#
#         # Thread-safe print output
#         with print_lock:
#             if vers_device_SN == sudi_device_sn and vers_device_PID == sudi_device_pid:
#                 print(f"Output from {new_hostname}: Serial {sudi_device_sn} and PID {sudi_device_pid} from {new_hostname} PASSED Validation")
#             else:
#                 print(f"Output from {new_hostname}: Serial {vers_device_PID} and PID {vers_device_SN} from {new_hostname} FAILED Validation")
#
#     except Exception as e:
#         with print_lock:
#             print(f"Failed to connect (IOS-XE) to {new_hostname}: {e}")


def main():
    global trust_store

    # Extract and Download Trusted Root and Intermediate Certificates
    # Should be done intermittently to save on processing
    # extract_urls_from_page_and_download(page_url)

    # Create trust store for validating certificates later, only do this once
    trust_store = create_trust_store_from_directory(trusted_cert_directory)

    # import Inventory to check
    inventory = import_inventory(csv_file_path)
    # inventory = test_servers

    # Shotgun SNMP all devices to determine known and compatible cisco devices for validation
    updated_inventory = pollsnmp.main(inventory, community, oid_group)
    print(updated_inventory)
    # Define the number of threads for the thread pool
    max_threads = len(updated_inventory)  # Adjust as needed

    # # Create a thread pool and connect to each server
    with ThreadPoolExecutor(max_threads) as executor:
        executor.map(ssh_connect_and_execute, updated_inventory)


if __name__ == "__main__":
    main()
