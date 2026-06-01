#!/usr/bin/env python3
"""
Multi-portal HTTP server launcher for localhost
Serves all portals on different ports:
- Citizen: http://localhost:3000
- Officer: http://localhost:3001
- Storage Admin: http://localhost:3002
- PKI Admin: http://localhost:3003
- Third-party: http://localhost:3004
"""

import http.server
import socketserver
import threading
import os
import sys
import json
import subprocess
import tempfile
from pathlib import Path

PORTALS = {
    3000: ("citizen.html", "Citizen Portal"),
    3001: ("officer.html", "Officer Portal"),
    3002: ("storage.html", "Storage Admin"),
    3003: ("pki.html", "PKI Admin"),
    3004: ("thirdparty.html", "Third-party Portal"),
}

class SimpleHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Serve the portal file for root path
        if self.path == '/' or self.path == '':
            self.path = f'/{self.portal_file}'
        return super().do_GET()

    def do_POST(self):
        if self.path == '/__keypair':
            self._handle_keypair_request()
            return
        if self.path == '/__sign':
            self._handle_sign_request()
            return
        self.send_error(404, "Not Found")

    def _handle_keypair_request(self):
        try:
            content_length = int(self.headers.get('Content-Length', '0'))
            raw_body = self.rfile.read(content_length).decode('utf-8') if content_length else '{}'
            payload = json.loads(raw_body or '{}')
            algorithm = (payload.get('algorithm') or 'ML-DSA-44').strip()

            if algorithm != 'ML-DSA-44':
                self._send_json(400, {'error': 'Only ML-DSA-44 is supported'})
                return

            openssl_bin = os.environ.get('OPENSSL_BIN', '/opt/openssl/apps/openssl')
            openssl_conf = os.environ.get('OPENSSL_CONF', '/opt/openssl/apps/openssl.cnf')
            openssl_modules = os.environ.get('OPENSSL_MODULES', '/opt/openssl/providers')
            openssl_lib_dir = os.environ.get('OPENSSL_LIB_DIR', '/opt/openssl')

            if not os.path.exists(openssl_bin):
                self._send_json(500, {'error': f'OpenSSL binary not found: {openssl_bin}'})
                return

            env = os.environ.copy()
            env['OPENSSL_CONF'] = openssl_conf
            env['OPENSSL_MODULES'] = openssl_modules
            env['LD_LIBRARY_PATH'] = openssl_lib_dir

            with tempfile.TemporaryDirectory() as tmpdir:
                priv_path = Path(tmpdir) / 'officer_private.pem'
                pub_path = Path(tmpdir) / 'officer_public.pem'

                subprocess.run([openssl_bin, 'genpkey', '-algorithm', 'ML-DSA-44', '-out', str(priv_path)], check=True, capture_output=True, env=env)
                subprocess.run([openssl_bin, 'pkey', '-in', str(priv_path), '-pubout', '-out', str(pub_path)], check=True, capture_output=True, env=env)

                private_key_pem = priv_path.read_text(encoding='utf-8')
                public_key_pem = pub_path.read_text(encoding='utf-8')

            self._send_json(200, {
                'algorithm': 'ML-DSA-44',
                'public_key_pem': public_key_pem,
                'private_key_pem': private_key_pem,
            })
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode('utf-8', errors='replace') if exc.stderr else str(exc)
            self._send_json(500, {'error': f'Keypair generation failed: {stderr}'})
        except Exception as exc:
            self._send_json(500, {'error': str(exc)})

    def _handle_sign_request(self):
        try:
            content_length = int(self.headers.get('Content-Length', '0'))
            raw_body = self.rfile.read(content_length).decode('utf-8') if content_length else '{}'
            payload = json.loads(raw_body or '{}')
            document_base64 = (payload.get('document_base64') or '').strip()
            private_key_pem = (payload.get('private_key_pem') or '').strip()

            if not document_base64:
                self._send_json(400, {'error': 'document_base64 is required'})
                return
            if not private_key_pem:
                self._send_json(400, {'error': 'private_key_pem is required for officer signing'})
                return

            openssl_bin = os.environ.get('OPENSSL_BIN', '/opt/openssl/apps/openssl')
            openssl_conf = os.environ.get('OPENSSL_CONF', '/opt/openssl/apps/openssl.cnf')
            openssl_modules = os.environ.get('OPENSSL_MODULES', '/opt/openssl/providers')
            openssl_lib_dir = os.environ.get('OPENSSL_LIB_DIR', '/opt/openssl')

            if not os.path.exists(openssl_bin):
                self._send_json(500, {'error': f'OpenSSL binary not found: {openssl_bin}'})
                return

            env = os.environ.copy()
            env['OPENSSL_CONF'] = openssl_conf
            env['OPENSSL_MODULES'] = openssl_modules
            env['LD_LIBRARY_PATH'] = openssl_lib_dir

            import base64
            doc_bytes = base64.b64decode(document_base64)

            with tempfile.TemporaryDirectory() as tmpdir:
                tmpdir_path = Path(tmpdir)
                priv_path = tmpdir_path / 'officer_private.pem'
                msg_path = tmpdir_path / 'message.bin'
                sig_path = tmpdir_path / 'signature.bin'

                priv_path.write_text(private_key_pem, encoding='utf-8')
                msg_path.write_bytes(doc_bytes)

                subprocess.run(
                    [openssl_bin, 'pkeyutl', '-sign', '-rawin', '-inkey', str(priv_path), '-in', str(msg_path), '-out', str(sig_path)],
                    check=True,
                    capture_output=True,
                    env=env,
                )

                signature_b64 = base64.b64encode(sig_path.read_bytes()).decode('ascii')

            self._send_json(200, {
                'signature': signature_b64,
                'signature_algorithm': 'ML-DSA',
            })
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode('utf-8', errors='replace') if exc.stderr else str(exc)
            self._send_json(500, {'error': f'Signing failed: {stderr}'})
        except Exception as exc:
            self._send_json(500, {'error': str(exc)})

    def _send_json(self, status_code, payload):
        data = json.dumps(payload).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(data)

    def end_headers(self):
        # Add CORS headers for API calls
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def log_message(self, format, *args):
        # Custom logging
        print(f"[{self.portal_name}] {format % args}")

def run_portal_server(port, file, name):
    """Run a single portal server on the specified port"""
    # Create a handler with portal info
    class PortalHandler(SimpleHTTPRequestHandler):
        portal_file = file
        portal_name = name
    
    handler = PortalHandler
    
    try:
        with socketserver.TCPServer(("", port), handler) as httpd:
            print(f"✓ {name} running on http://localhost:{port}")
            httpd.serve_forever()
    except OSError as e:
        print(f"✗ Failed to start {name} on port {port}: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    # Get portal directory
    portal_dir = Path(__file__).parent.absolute()
    os.chdir(portal_dir)
    
    print(f"Starting portals from: {portal_dir}")
    print("")
    
    # Start each portal in a separate thread
    threads = []
    for port, (file, name) in PORTALS.items():
        # Check if file exists
        if not (portal_dir / file).exists():
            print(f"✗ {file} not found", file=sys.stderr)
            continue
        
        thread = threading.Thread(target=run_portal_server, args=(port, file, name), daemon=True)
        thread.start()
        threads.append(thread)
    
    print("")
    print("Available portals:")
    print("  - Citizen Portal:    http://localhost:3000")
    print("  - Officer Portal:    http://localhost:3001")
    print("  - Storage Admin:     http://localhost:3002")
    print("  - PKI Admin:         http://localhost:3003")
    print("  - Third-party:       http://localhost:3004")
    print("")
    print("Note: Make sure backend APIs are running at http://localhost:8080 (DMZ Gateway)")
    print("Press Ctrl+C to stop all servers")
    print("")
    
    # Keep main thread alive
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print("\nShutting down all portals...")
        sys.exit(0)

if __name__ == "__main__":
    main()
