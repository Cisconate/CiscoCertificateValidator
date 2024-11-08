import requests
from bs4 import BeautifulSoup
from OpenSSL import crypto
import os

page_url = 'https://www.cisco.com/security/pki/'
output_file_path = 'RootCerts.txt'
urls = []
trusted_cert_directory = "trusted_certs"
service_Account_Username = "svc_python"
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


def download_cer_certificate(url, output_file):
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
    Extract all URLs from the links in the specified HTML page.

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
                download_cer_certificate(link.get('href'), link.text)
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


def validate_certificate_file(cert_file, store):
    """
    Verify a certificate against a given X509Store (trust store).

    Parameters:
    - cert_file (str): Path to the certificate file to be verified.
    - store (X509Store): X509Store object containing trusted certificates.

    Returns:
    - bool: True if verification succeeds, False otherwise.
    """

    # Get the absolute path based on the current script's directory
    file_path = os.path.join(os.path.dirname(__file__), cert_file)


    try:
        with open(file_path, "rb") as f:
            cert_data = f.read()
            certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

        # Create a certificate context and try to verify it
        store_ctx = crypto.X509StoreContext(store, certificate)
        store_ctx.verify_certificate()
        print(f"Certificate {file_path} verified successfully.")
        return True
    except crypto.X509StoreContextError as e:
        print(f"Certificate {file_path} verification failed: {e}")
        return False


if __name__ == "__main__":

    # Create the trusted certs directory if it doesn't exist
    os.makedirs(trusted_cert_directory, exist_ok=True)

    # Extract and Download Trusted Root and Intermediate Certificates
    # Should be done intermittently to save on processing
    # extract_urls_from_page_and_download(page_url)

    # Load all certificates in the directory into a trust store
    # Every time for faster validations
    trust_store = create_trust_store_from_directory(trusted_cert_directory)

    # Validate ad-hoc certificate as test
    validate_certificate_live(test_cert, trust_store)
    validate_certificate_file("test_cert", trust_store)

