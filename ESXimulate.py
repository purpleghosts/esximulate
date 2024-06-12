import http.server
import socketserver
import ssl
import logging
import threading
import sys
import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

# Configure the logger
logging.basicConfig(filename='esximulate.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Root path to serve the ESXi web client content
WEB_DIR = './'

# ASCII Art Banner
BANNER = r"""
 ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄       ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄       ▄▄  ▄         ▄  ▄            ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌     ▐░▌▐░░░░░░░░░░░▌▐░░▌     ▐░░▌▐░▌       ▐░▌▐░▌          ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀  ▐░▌   ▐░▌  ▀▀▀▀█░█▀▀▀▀ ▐░▌░▌   ▐░▐░▌▐░▌       ▐░▌▐░▌          ▐░█▀▀▀▀▀▀▀█░▌ ▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ 
▐░▌          ▐░▌            ▐░▌ ▐░▌       ▐░▌     ▐░▌▐░▌ ▐░▌▐░▌▐░▌       ▐░▌▐░▌          ▐░▌       ▐░▌     ▐░▌     ▐░▌          
▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄    ▐░▐░▌        ▐░▌     ▐░▌ ▐░▐░▌ ▐░▌▐░▌       ▐░▌▐░▌          ▐░█▄▄▄▄▄▄▄█░▌     ▐░▌     ▐░█▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌    ▐░▌         ▐░▌     ▐░▌  ▐░▌  ▐░▌▐░▌       ▐░▌▐░▌          ▐░░░░░░░░░░░▌     ▐░▌     ▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀█░▌   ▐░▌░▌        ▐░▌     ▐░▌   ▀   ▐░▌▐░▌       ▐░▌▐░▌          ▐░█▀▀▀▀▀▀▀█░▌     ▐░▌     ▐░█▀▀▀▀▀▀▀▀▀ 
▐░▌                    ▐░▌  ▐░▌ ▐░▌       ▐░▌     ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌          ▐░▌       ▐░▌     ▐░▌     ▐░▌          
▐░█▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄█░▌ ▐░▌   ▐░▌  ▄▄▄▄█░█▄▄▄▄ ▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░▌       ▐░▌     ▐░▌     ▐░█▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌     ▐░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌     ▐░▌     ▐░░░░░░░░░░░▌
 ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀       ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀       ▀       ▀▀▀▀▀▀▀▀▀▀▀ 

Purple Ghosts (C) 2024
https://github.com/purpleghosts/esximulate
"""

print(BANNER)

class HTTPRedirectHandler(http.server.SimpleHTTPRequestHandler):
    """Handler for HTTP requests that redirects to HTTPS"""
    server_version = "VMware ESXi Server httpd"
    sys_version = ""

    def do_GET(self):
        """Handle GET requests by redirecting to HTTPS"""
        try:
            logging.info(f"HTTP redirect from {self.client_address}")
            self.send_response(301)
            self.send_header('Location', f'https://{self.headers["Host"]}{self.path}')
            self.end_headers()
        except Exception as e:
            logging.error(f"Exception in do_GET: {e}")

    def send_error(self, code, message=None, explain=None):
        """Send and log an error reply with minimal information"""
        self.log_error("code %d, message %s", code, message)
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Server', self.server_version)
        self.end_headers()
        error_message = f"Error code: {code}".encode('utf-8')
        self.wfile.write(error_message)

    def end_headers(self):
        """Set custom server header"""
        super().end_headers()

    def handle_one_request(self):
        """Handle a single HTTP request"""
        try:
            super().handle_one_request()
        except ConnectionResetError:
            logging.info(f"Connection reset by peer from {self.client_address}")
        except Exception as e:
            logging.error(f"Exception in handle_one_request: {e}")

class HTTPSRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Handler for HTTPS requests to serve ESXi web client content"""
    server_version = "VMware ESXi SOAP API 7.0.3"
    sys_version = ""

    def translate_path(self, path):
        """Translate the requested path to the appropriate file in WEB_DIR"""
        path = path.lstrip('/')
        if path == "":
            path = "ui/index.html"
        return os.path.join(WEB_DIR, path)

    def do_GET(self):
        """Handle GET requests to serve content or redirect"""
        try:
            if self.path == '/':
                self.send_response(301)
                self.send_header('Location', '/ui')
                self.end_headers()
                logging.info(f"Connection to console from {self.client_address}")
            else:
                logging.info(f"{self.client_address} are requesting {self.path}")
                super().do_GET()
        except Exception as e:
            logging.error(f"Exception in do_GET: {e}")

    def do_POST(self):
        """Handle POST requests to log login attempts"""
        try:
            if self.path == '/sdk/':
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length).decode('utf-8')
                logging.info(f"Login attempt from {self.client_address} with data: {post_data}")
                #self.send_response(200)
                #self.send_header('Content-Type', 'text/xml')
                #self.end_headers()
                #self.wfile.write(b'')
                super().do_GET()
            else:
                self.send_error(404, "File not found")
        except Exception as e:
            logging.error(f"Exception in do_POST: {e}")

    def send_error(self, code, message=None, explain=None):
        """Send and log an error reply with minimal information"""
        self.log_error("code %d, message %s", code, message)
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        error_message = f"Error code: {code}".encode('utf-8')
        self.wfile.write(error_message)

    def end_headers(self):
        """Set custom server header"""
        super().end_headers()

    def handle_one_request(self):
        """Handle a single HTTP request"""
        try:
            super().handle_one_request()
        except ConnectionResetError:
            logging.info(f"Connection reset by peer from {self.client_address}")
        except Exception as e:
            logging.error(f"Exception in handle_one_request: {e}")

def generate_cert(common_name, force=False):
    """Generate a self-signed certificate if it doesn't exist or force is True"""
    cert_filename = f"{common_name}.pem"
    if os.path.exists(cert_filename) and not force:
        print(f"Certificate already exists: {cert_filename}")
        return cert_filename

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Certificate subject and issuer information
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Palo Alto"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"VMware, Inc"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"VMware ESXi Server Default Certificate"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, u"ssl-certificates@vmware.com"),
    ])

    # Create the certificate
    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(common_name)]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    # Save the private key and certificate to files
    with open(cert_filename, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        ))

        f.write(certificate.public_bytes(Encoding.PEM))

    print(f"Certificate and private key generated and saved in {cert_filename} with Common Name: {common_name}")
    return cert_filename

def run_http():
    """Run HTTP server to redirect requests to HTTPS"""
    with socketserver.TCPServer(("", 80), HTTPRedirectHandler) as httpd:
        print("Serving HTTP on port 80...")
        try:
            httpd.serve_forever()
        except Exception as e:
            logging.error(f"Error in HTTP server: {e}")

def run_https(cert_filename):
    """Run HTTPS server to serve ESXi web client content"""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=cert_filename, keyfile=cert_filename)

    with socketserver.TCPServer(("", 443), HTTPSRequestHandler) as httpd:
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        print("Serving HTTPS on port 443...")
        try:
            httpd.serve_forever()
        except Exception as e:
            logging.error(f"Error in HTTPS server: {e}")

if __name__ == '__main__':
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python honeypot.py <common_name> [--force]")
        sys.exit(1)

    common_name = sys.argv[1]
    force_regenerate = len(sys.argv) == 3 and sys.argv[2] == '--force'
    
    cert_filename = generate_cert(common_name, force=force_regenerate)

    threading.Thread(target=run_http).start()
    threading.Thread(target=run_https, args=(cert_filename,)).start()
