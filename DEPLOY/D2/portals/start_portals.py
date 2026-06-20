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

LOCAL_PRIVATE_ROOT = Path(os.environ.get("LOCAL_PRIVATE_DIR", "/app/local_private")).resolve()

KEY_PATHS = {
    ("officer", "signing"): ("officers", "signing_private.pem", "signing_public.pem"),
    ("officer", "mtls"): ("officers", "mtls_private.pem", "mtls_public.pem"),
    ("thirdparty", "mtls"): ("thirdparties", "mtls_private.pem", "mtls_public.pem"),
}

class SimpleHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Serve the portal file for root path
        if self.path == '/' or self.path == '':
            self.path = f'/{self.portal_file}'
        return super().do_GET()

    def do_POST(self):
        if self.path == '/__keypair':
            self._send_json(410, {
                'error': 'server_side_key_generation_disabled',
                'message': 'Generate key material on the client with DEPLOY/D2/scripts/generate_client_key_material.ps1.',
            })
            return
        if self.path == '/__local-key':
            self._send_json(410, {
                'error': 'server_side_private_key_storage_disabled',
                'message': 'Private keys must stay on the client and are not loaded by the portal server.',
            })
            return
        if self.path == '/__sign':
            self._handle_sign_request()
            return
        self.send_error(404, "Not Found")

    def _key_files(self, role, subject_id, key_name):
        if not subject_id:
            raise ValueError("subject_id is required")
        safe_subject = "".join(ch for ch in subject_id if ch.isalnum() or ch in ("_", "-", "."))
        if safe_subject != subject_id:
            raise ValueError("subject_id contains unsupported characters")
        mapping = KEY_PATHS.get((role, key_name))
        if not mapping:
            raise ValueError("unsupported role/key_name")
        role_dir, private_name, public_name = mapping
        base = (LOCAL_PRIVATE_ROOT / role_dir / safe_subject).resolve()
        if not str(base).startswith(str(LOCAL_PRIVATE_ROOT)):
            raise ValueError("invalid key path")
        return base, base / private_name, base / public_name

    def _handle_keypair_request(self):
        try:
            content_length = int(self.headers.get('Content-Length', '0'))
            raw_body = self.rfile.read(content_length).decode('utf-8') if content_length else '{}'
            payload = json.loads(raw_body or '{}')
            algorithm = (payload.get('algorithm') or 'ML-DSA-44').strip()
            role = (payload.get('role') or '').strip()
            subject_id = (payload.get('subject_id') or '').strip()
            key_name = (payload.get('key_name') or '').strip()
            save_to_file = bool(payload.get('save_to_file'))

            if algorithm not in ('ML-DSA-44', 'EC-P384', 'ECDSA-P384'):
                self._send_json(400, {'error': 'Only ML-DSA-44 and EC-P384 are supported'})
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
                priv_path = Path(tmpdir) / 'private.pem'
                pub_path = Path(tmpdir) / 'public.pem'

                if algorithm == 'ML-DSA-44':
                    subprocess.run([openssl_bin, 'genpkey', '-algorithm', 'ML-DSA-44', '-out', str(priv_path)], check=True, capture_output=True, env=env)
                else:
                    subprocess.run([openssl_bin, 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:secp384r1', '-out', str(priv_path)], check=True, capture_output=True, env=env)
                subprocess.run([openssl_bin, 'pkey', '-in', str(priv_path), '-pubout', '-out', str(pub_path)], check=True, capture_output=True, env=env)

                private_key_pem = priv_path.read_text(encoding='utf-8')
                public_key_pem = pub_path.read_text(encoding='utf-8')

            private_key_path = None
            public_key_path = None
            if save_to_file:
                base, private_file, public_file = self._key_files(role, subject_id, key_name)
                base.mkdir(parents=True, exist_ok=True)
                private_file.write_text(private_key_pem, encoding='utf-8')
                public_file.write_text(public_key_pem, encoding='utf-8')
                try:
                    os.chmod(private_file, 0o600)
                except OSError:
                    pass
                private_key_path = str(private_file)
                public_key_path = str(public_file)

            self._send_json(200, {
                'algorithm': 'ML-DSA-44' if algorithm == 'ML-DSA-44' else 'EC-P384',
                'public_key_pem': public_key_pem,
                'private_key_pem': private_key_pem,
                'private_key_path': private_key_path,
                'public_key_path': public_key_path,
            })
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode('utf-8', errors='replace') if exc.stderr else str(exc)
            self._send_json(500, {'error': f'Keypair generation failed: {stderr}'})
        except Exception as exc:
            self._send_json(500, {'error': str(exc)})

    def _handle_local_key_request(self):
        try:
            content_length = int(self.headers.get('Content-Length', '0'))
            raw_body = self.rfile.read(content_length).decode('utf-8') if content_length else '{}'
            payload = json.loads(raw_body or '{}')
            action = (payload.get('action') or 'get').strip()
            role = (payload.get('role') or '').strip()
            subject_id = (payload.get('subject_id') or '').strip()
            key_name = (payload.get('key_name') or '').strip()
            base, private_file, public_file = self._key_files(role, subject_id, key_name)

            if action == 'get':
                if not private_file.exists():
                    self._send_json(404, {'error': 'private key not found', 'private_key_path': str(private_file)})
                    return
                public_key_pem = public_file.read_text(encoding='utf-8') if public_file.exists() else ''
                self._send_json(200, {
                    'private_key_pem': private_file.read_text(encoding='utf-8'),
                    'public_key_pem': public_key_pem,
                    'private_key_path': str(private_file),
                    'public_key_path': str(public_file),
                })
                return

            if action == 'put':
                private_key_pem = (payload.get('private_key_pem') or '').strip()
                public_key_pem = (payload.get('public_key_pem') or '').strip()
                if not private_key_pem:
                    self._send_json(400, {'error': 'private_key_pem is required'})
                    return
                base.mkdir(parents=True, exist_ok=True)
                private_file.write_text(private_key_pem + "\n", encoding='utf-8')
                if public_key_pem:
                    public_file.write_text(public_key_pem + "\n", encoding='utf-8')
                try:
                    os.chmod(private_file, 0o600)
                except OSError:
                    pass
                self._send_json(200, {'private_key_path': str(private_file), 'public_key_path': str(public_file)})
                return

            self._send_json(400, {'error': 'unsupported action'})
        except Exception as exc:
            self._send_json(500, {'error': str(exc)})

    def _handle_sign_request(self):
        self._send_json(410, {
            'error': 'server_side_signing_disabled',
            'message': 'Sign documents on the client with the local business private key, then submit the signature.',
        })

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
