import paramiko
import threading
import time
from concurrent.futures import ThreadPoolExecutor

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

# Sample data: list of server information
servers = [
    {"hostname": "192.168.30.1", "username": "nstapp", "password": "Cisco1234%67", "software": "IOS-XE"},
    {"hostname": "192.168.30.2", "username": "nstapp", "password": "Cisco1234%67", "software": "ISR"},
    {"hostname": "192.168.30.3", "username": "nstapp", "password": "Cisco1234%67", "software": "ASA"},
    {"hostname": "192.168.30.74", "username": "nstapp", "password": "Cisco1234%67", "software": "IOS-XE"}
]

# Lock for thread-safe print statements
print_lock = threading.Lock()


def ssh_connect(server):
    """
    Connects to a server over SSH and executes a command.

    Parameters:
    - server (dict): A dictionary containing server connection details.
    """
    hostname = server["hostname"]
    username = server["username"]
    password = server["password"]
    software = server["software"]

    try:
        # Initialize SSH client
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the server
        if software == "IOS-XE":
            client.connect(hostname=hostname, username=username, password=password)
            print(f"Connected to {hostname}")
            IOS_XE_verify_SN_PID_2(client,hostname)

    except Exception as e:
        with print_lock:
            print(f"Failed to connect (MAIN) to {hostname}: {e}")

    finally:
        client.close()

def IOS_XE_verify_SN_PID(new_client, new_hostname):
    """
    Pulls trusted pki info, parses for SN and PID, then compares to sh version output

    Parameters:
    - new_client (ssh connection): A dictionary containing server connection details.
    - new_hostname (hostname): A string containing server hostname.
    """
    try:
        # Set terminal length
        # stdin, stdout, stderr = new_client.exec_command("terminal length 0")
        # output = stdout.read().decode().strip()

        # List all PID/SN (there can be multiple) and check for a match
        stdin, stdout, stderr = new_client.exec_command("show crypto pki certificate verbose | i serialNumber=PID:")
        output = stdout.read().decode().strip()

        # Ensure multiple lines of output are curated to one copy
        first_line = output.split('\r', 1)[0]
        text_output = first_line.split(" SN:")

        # Curate SN and PID
        sudi_device_sn = text_output[-1]
        sudi_device_pid = text_output[0].split("PID:")[1]

        # Thread-safe print output
        with print_lock:
            print(f"Output from {new_hostname}: SUDI Device SN - {sudi_device_sn}")
            print(f"Output from {new_hostname}: SUDI Device PID - {sudi_device_pid}")

        # List all PID/SN (there can be multiple) and check for a match
        stdin, stdout, stderr = new_client.exec_command("show version | beg Model Number")
        output = stdout.read().decode().strip()

        # Separate each line for easy parsing
        lines = output.split('\r')

        # Curate "Show version" SN, and PID
        vers_device_PID = lines[0].split(': ')[1]
        vers_device_SN = lines[1].split(': ')[1]

        # Thread-safe print output
        with print_lock:
            print(f"Output from {new_hostname}: Vers Device SN - {vers_device_SN}")
            print(f"Output from {new_hostname}: Vers Device PID - {vers_device_PID}")

    except Exception as e2:
        with print_lock:
            print(f"Failed to connect (IOS-XE) to {new_hostname}: {e2}")

def IOS_XE_verify_SN_PID_2(new_client, new_hostname):
    """
    Pulls trusted pki info, parses for SN and PID, then compares to sh version output

    Parameters:
    - new_client (ssh connection): A dictionary containing server connection details.
    - new_hostname (hostname): A string containing server hostname.
    """
    try:
        # Invoke a shell session
        shell = new_client.invoke_shell()

        # Allow the shell to initialize (may need to wait a moment for prompt)
        time.sleep(2)

        # Send Command
        shell.send("show crypto pki certificate verbose | i serialNumber=PID:\n")
        time.sleep(2)  # Allow some time for the command to execute

        # Read the output after sending the command
        output = shell.recv(1024).decode('utf-8')  # Adjust buffer size as needed

        # Ensure multiple lines of output are curated to one copy
        first_line = output.split('\r')[2]

        # Remove duplicate lines
        text_output = first_line.split(" SN:")

        # Curate SN and PID
        sudi_device_sn = text_output[-1]
        sudi_device_pid = text_output[0].split("PID:")[1]

        # Send Command
        shell.send("show version | beg Model Number\n")
        time.sleep(2)  # Allow some time for the command to execute

        # Read the output after sending the command
        output = shell.recv(1024).decode('utf-8')  # Adjust buffer size as needed

        # Separate each line for easy parsing
        lines = output.split('\r')

        # Curate "Show version" SN, and PID
        vers_device_PID = lines[1].split(': ')[1]
        vers_device_SN = lines[2].split(': ')[1]

        # Thread-safe print output
        with print_lock:
            if vers_device_SN == sudi_device_sn and vers_device_PID == sudi_device_pid:
                print(f"Output from {new_hostname}: Serial {sudi_device_sn} and PID {sudi_device_pid} from {new_hostname} PASSED Validation")
            else:
                print(f"Output from {new_hostname}: Serial {vers_device_PID} and PID {vers_device_SN} from {new_hostname} FAILED Validation")

    except Exception as e2:
        with print_lock:
            print(f"Failed to connect (IOS-XE) to {new_hostname}: {e2}")

def main():
    # Define the number of threads for the thread pool
    max_threads = len(servers)  # Adjust as needed

    # Create a thread pool and connect to each server
    with ThreadPoolExecutor(max_threads) as executor:
        executor.map(ssh_connect, servers)


if __name__ == "__main__":
    main()
