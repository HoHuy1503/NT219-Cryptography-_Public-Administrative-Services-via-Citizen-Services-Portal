from flask import Flask, request, jsonify
import base64, hashlib, logging, os, sys, time, uuid, requests, json, io, shutil
from datetime import datetime, timezone, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.oid import ObjectIdentifier
import subprocess
import qrcode
import tempfile

logging.basicConfig(level=logging.INFO,
  format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
  stream=sys.stdout)
logger = logging.getLogger(__name__)

app = Flask(__name__)

from state_paths import (
    MLDSA_DIR,
    MLDSA_PRIV_CANDIDATES,
    MLDSA_PRIV_PEM,
    MLDSA_PUBLISHED_JSON,
    MLDSA_PUB_CANDIDATES,
    MLDSA_PUB_PEM,
    PKI_CA_CERT,
    PKI_CA_KEY,
    PKI_CERT_STORE,
    PKI_DIR,
    STATE_ROOT,
    ensure_state_dirs,
    first_existing,
    read_bytes_file,
    read_text_file,
    write_bytes_file,
    write_text_file,
)

storage_service_url = os.environ.get("STORAGE_SERVICE_URL", "http://storage-service:9003")
ML_ENABLED = os.environ.get("ML_ENABLED", "true").lower() == "true"
ML_ALG_DSA = os.environ.get("ML_ALG_DSA", "ML-DSA-44")
ML_ALG_KEM = os.environ.get("ML_ALG_KEM", "ML-KEM-512")
OPENSSL_BIN = os.environ.get("OPENSSL_BIN", "/opt/openssl/apps/openssl")
OPENSSL_LIB_DIR = os.environ.get("OPENSSL_LIB_DIR", "/opt/openssl")
OPENSSL_MODULES = os.environ.get("OPENSSL_MODULES", "/opt/openssl/ossl-modules")
STATE_DIR = str(STATE_ROOT)
PKI_SUBJECT_C = os.environ.get("PKI_SUBJECT_C", "VN")
PKI_SUBJECT_O = os.environ.get("PKI_SUBJECT_O", "OFFICER")
PKI_SUBJECT_ST = os.environ.get("PKI_SUBJECT_ST", "HCM")
PKI_SUBJECT_L = os.environ.get("PKI_SUBJECT_L", "Q12")
PKI_SUBJECT_OU = os.environ.get("PKI_SUBJECT_OU", "CA Q12")
OPENSSL_CONF_PATH = os.environ.get("OPENSSL_CONF", "/opt/openssl/apps/openssl.cnf")
BROWSER_CLIENT_CA_DIR = Path(os.environ.get("BROWSER_CLIENT_CA_DIR", "/state/browser_client_ca")).resolve()
BROWSER_CLIENT_CA_CERT = Path(os.environ.get("BROWSER_CLIENT_CA_CERT", str(BROWSER_CLIENT_CA_DIR / "portal-client-ca.crt"))).resolve()
BROWSER_CLIENT_CA_KEY = Path(os.environ.get("BROWSER_CLIENT_CA_KEY", str(BROWSER_CLIENT_CA_DIR / "portal-client-ca.key"))).resolve()

ML_DSA_PUBLIC_KEY_OIDS = {
  bytes.fromhex("0609608648016503040311"),  # ML-DSA-44
  bytes.fromhex("0609608648016503040312"),  # ML-DSA-65
  bytes.fromhex("0609608648016503040313"),  # ML-DSA-87
}

def _build_openssl_env():
  env = os.environ.copy()
  if OPENSSL_LIB_DIR:
    env["LD_LIBRARY_PATH"] = f"{OPENSSL_LIB_DIR}:{env['LD_LIBRARY_PATH']}" if env.get("LD_LIBRARY_PATH") else OPENSSL_LIB_DIR
  if OPENSSL_MODULES:
    env["OPENSSL_MODULES"] = OPENSSL_MODULES
  if OPENSSL_CONF_PATH:
    env["OPENSSL_CONF"] = OPENSSL_CONF_PATH
  return env


def _openssl_available():
  return os.path.exists(OPENSSL_BIN)


def _run_openssl(args):
  if not os.path.exists(OPENSSL_BIN):
    raise RuntimeError(f"Configured OpenSSL binary not found: {OPENSSL_BIN}")
  return subprocess.run(
    [OPENSSL_BIN] + args,
    check=True,
    capture_output=True,
    env=_build_openssl_env(),
  )


def _pem_to_der(pem_text):
  lines = [
    line.strip()
    for line in pem_text.strip().splitlines()
    if line.strip() and not line.startswith("-----")
  ]
  return base64.b64decode("".join(lines), validate=True)


def _is_ml_dsa_public_key_pem(public_key_pem):
  try:
    der = _pem_to_der(public_key_pem)
  except Exception:
    return False
  return any(oid in der[:64] for oid in ML_DSA_PUBLIC_KEY_OIDS)


def _openssl_cert_metadata(cert_pem):
  with tempfile.TemporaryDirectory() as tmpdir:
    cert_file = Path(tmpdir) / "cert.pem"
    cert_file.write_text(cert_pem, encoding="utf-8")
    result = _run_openssl(["x509", "-in", str(cert_file), "-noout", "-serial", "-subject", "-issuer", "-dates"])
  lines = result.stdout.decode("utf-8", errors="replace").splitlines()
  data = {}
  for line in lines:
    if "=" in line:
      key, value = line.split("=", 1)
      data[key.strip()] = value.strip()

  def parse_openssl_date(value):
    normalized = " ".join((value or "").split())
    dt = datetime.strptime(normalized, "%b %d %H:%M:%S %Y GMT")
    return dt.replace(tzinfo=timezone.utc).isoformat()

  return {
    "serial": data.get("serial", ""),
    "subject": data.get("subject", ""),
    "issuer": data.get("issuer", ""),
    "not_before": parse_openssl_date(data.get("notBefore", "")),
    "not_after": parse_openssl_date(data.get("notAfter", "")),
  }


def _cert_uses_ml_dsa(cert_path):
  try:
    result = _run_openssl(["x509", "-in", str(cert_path), "-noout", "-text"])
    text = result.stdout.decode("utf-8", errors="replace")
    return "Public Key Algorithm: ML-DSA" in text and "Signature Algorithm: ML-DSA" in text
  except Exception:
    return False


def _ensure_business_ca_files():
  ensure_state_dirs()
  ca_key_path = first_existing(PKI_CA_KEY)
  ca_cert_path = first_existing(PKI_CA_CERT)
  if ca_key_path and ca_cert_path and _cert_uses_ml_dsa(ca_cert_path):
    return ca_key_path, ca_cert_path

  timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
  for path in (ca_key_path, ca_cert_path):
    if path and path.exists():
      shutil.copy2(path, path.with_suffix(path.suffix + f".backup-{timestamp}"))

  subject = (
    f"/C={PKI_SUBJECT_C[:2].upper()}"
    f"/ST={PKI_SUBJECT_ST}"
    f"/L={PKI_SUBJECT_L}"
    f"/O={PKI_SUBJECT_O}"
    f"/OU={PKI_SUBJECT_OU}"
    "/CN=GovPortal Business Root CA"
  )
  PKI_DIR.mkdir(parents=True, exist_ok=True)
  _run_openssl(["genpkey", "-algorithm", ML_ALG_DSA, "-out", str(PKI_CA_KEY)])
  _run_openssl([
    "req", "-new", "-x509",
    "-key", str(PKI_CA_KEY),
    "-out", str(PKI_CA_CERT),
    "-days", "3650",
    "-subj", subject,
  ])
  _run_openssl(["pkey", "-in", str(PKI_CA_KEY), "-pubout", "-out", str(PKI_CA_PUBLIC)])
  return PKI_CA_KEY, PKI_CA_CERT


def _validate_ml_dsa_public_key(public_key_pem):
  if not public_key_pem or not public_key_pem.strip().startswith("-----BEGIN PUBLIC KEY-----"):
    raise ValueError("Invalid public key PEM")
  if not _is_ml_dsa_public_key_pem(public_key_pem):
    raise ValueError("Only ML-DSA public keys are supported for business signing")
  return True


def _validate_ec_public_key(public_key_pem):
  try:
    public_key = load_pem_public_key(public_key_pem.encode('utf-8'))
  except Exception:
    raise ValueError("Invalid EC public key PEM")
  if not isinstance(public_key, ec.EllipticCurvePublicKey):
    raise ValueError("mTLS client certificates require an EC public key")
  if public_key.curve.name not in ("secp256r1", "secp384r1"):
    raise ValueError("Only P-256 or P-384 EC public keys are supported for mTLS")
  return public_key


def _load_current_officer_public_key_from_storage(officer_id):
  response = requests.get(f"{storage_service_url}/api/storage/internal/officers/{officer_id}/current-key", timeout=10)
  data = response.json() if response.content else {}
  if response.status_code != 200:
    raise RuntimeError(data.get("error") or "Unable to load officer public key from storage")

  key = data.get("key") or {}
  public_key_pem = (key.get("public_key_pem") or "").strip()
  if not public_key_pem:
    raise RuntimeError("Storage response missing officer public key")
  _validate_ml_dsa_public_key(public_key_pem)
  return public_key_pem

FILE_PUBLIC_KEY_PATH = str(MLDSA_PUBLISHED_JSON)

def log_event(event, extra=None):
  payload = {"event": event}
  if extra:
    payload.update(extra)
  logger.info(str(payload))

def archive_document(payload):
  headers = {"Content-Type": "application/json"}
  try:
    response = requests.post(
      f"{storage_service_url}/api/storage/documents",
      json=payload,
      headers=headers,
      timeout=10,
    )
    return response
  except Exception as e:
    logger.error(f"Archive request failed: {e}")
    raise

def publish_public_key_to_state(public_key_b64):
  # Persist the public key to the local state directory so services
  # can read it. This deployment does not use Vault; writes must succeed
  # or be logged but will not attempt any Vault operations.
  try:
    pem = "-----BEGIN ML-DSA PUBLIC KEY-----\n" + public_key_b64 + "\n-----END ML-DSA PUBLIC KEY-----"
    payload = {
      "kid": "mldsa-doc-v1",
      "alg": "ML-DSA",
      "kty": "PQ",
      "pub_b64": public_key_b64,
      "pub_pem": pem,
      "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    os.makedirs(MLDSA_DIR, exist_ok=True)
    with open(FILE_PUBLIC_KEY_PATH, 'w', encoding='utf-8') as f:
      json.dump(payload, f)
    return True
  except Exception as e:
    logger.warning(f"Failed to write public key to local state: {e}")
    return False

def read_public_key_from_state():
  # Read the persisted public key from the local state file only.
  try:
    if os.path.exists(FILE_PUBLIC_KEY_PATH):
      with open(FILE_PUBLIC_KEY_PATH, 'r', encoding='utf-8') as f:
        data = json.load(f)
      pub_pem = data.get('pub_pem')
      if isinstance(pub_pem, str) and pub_pem.strip():
        return pub_pem.strip()
      pub_b64 = data.get('pub_b64')
      if isinstance(pub_b64, str) and pub_b64.strip():
        return pub_b64.strip()
  except Exception as e:
    logger.warning(f"Failed to read ML public key from local state: {e}")
  return None

def _read_text(path):
  p = path if isinstance(path, Path) else Path(path)
  found = first_existing(p)
  if not found:
    return ""
  return read_text_file(found)


def _write_text(path, content):
  write_text_file(Path(path), content)


def _load_cert_store():
  try:
    raw = _read_text(PKI_CERT_STORE)
    if not raw.strip():
      return []
    data = json.loads(raw)
    if isinstance(data, list):
      return data
  except Exception as e:
    logger.warning(f"Failed to read cert store: {e}")
  return []


def _save_cert_store(items):
  _write_text(PKI_CERT_STORE, json.dumps(items, indent=2))


def _load_or_create_ca():
  return _ensure_business_ca_files()

def _issue_ml_officer_cert(common_name, organization, country="VN", state_or_province="HCM", locality="Q12", organizational_unit="CA Q12", officer_id=None, provided_public_key_pem=None, csr_pem=None):
  """
  Issue an ML-DSA business-signing certificate using a client-generated public key.
  The corresponding private key must stay on the officer's client machine/token.
  """
  if not _openssl_available():
    raise RuntimeError("OpenSSL not available for certificate generation")
  if not provided_public_key_pem and not csr_pem:
    raise RuntimeError("ML-DSA business certificate issuance requires a provided CSR or public key")

  if provided_public_key_pem:
    _validate_ml_dsa_public_key(provided_public_key_pem)
  ca_key_path, ca_cert_path = _ensure_business_ca_files()
  now = datetime.now(timezone.utc)
  
  with tempfile.TemporaryDirectory() as tmpdir:
    tmpdir_path = Path(tmpdir)
    ml_pub = tmpdir_path / "ml_pub.pem"
    csr_file = tmpdir_path / "officer.csr"
    cert_file = tmpdir_path / "officer.crt"
    ext_file = tmpdir_path / "cert_ext.cnf"
    _write_text(str(ext_file), "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n")

    if csr_pem:
      _write_text(str(csr_file), csr_pem)
      pub_result = _run_openssl(["req", "-in", str(csr_file), "-pubkey", "-noout"])
      ml_pub_pem = pub_result.stdout.decode("utf-8", errors="replace")
      _validate_ml_dsa_public_key(ml_pub_pem)
      if provided_public_key_pem and _pem_to_der(ml_pub_pem) != _pem_to_der(provided_public_key_pem):
        raise RuntimeError("CSR public key does not match provided public_key_pem")
      sign_args = [
        "x509", "-req",
        "-in", str(csr_file),
        "-CAkey", str(ca_key_path),
        "-CA", str(ca_cert_path),
        "-CAcreateserial",
        "-out", str(cert_file),
        "-days", "365",
        "-extfile", str(ext_file),
      ]
    else:
      ml_pub_pem = provided_public_key_pem
      _write_text(str(ml_pub), ml_pub_pem)
      subj = (
        f"/C={country[:2].upper()}"
        f"/ST={state_or_province}"
        f"/O={organization}"
        f"/OU={organizational_unit}"
        f"/CN={common_name}"
      )
      temp_key = tmpdir_path / "temp_key.pem"
      _run_openssl(["genpkey", "-algorithm", ML_ALG_DSA, "-out", str(temp_key)])
      _run_openssl(["req", "-new", "-key", str(temp_key), "-out", str(csr_file), "-subj", subj])
      sign_args = [
        "x509", "-req",
        "-in", str(csr_file),
        "-CAkey", str(ca_key_path),
        "-CA", str(ca_cert_path),
        "-CAcreateserial",
        "-force_pubkey", str(ml_pub),
        "-out", str(cert_file),
        "-days", "365",
        "-extfile", str(ext_file),
      ]

    _run_openssl(sign_args)
    
    cert_pem = cert_file.read_text(encoding='utf-8')
    ml_pub_b64 = base64.b64encode(ml_pub_pem.encode('utf-8')).decode('ascii')
    cert_meta = _openssl_cert_metadata(cert_pem)
    
    cert_id = f"cert-{uuid.uuid4().hex[:12]}"
    item = {
      "cert_id": cert_id,
      "officer_id": officer_id,
      "document_id": None,
      "purpose": "document_signing",
      "serial": cert_meta["serial"],
      "subject": cert_meta["subject"],
      "issuer": cert_meta["issuer"],
      "not_before": cert_meta["not_before"],
      "not_after": cert_meta["not_after"],
      "certificate": cert_pem,
      "public_key_pem": ml_pub_pem,
      "ml_public_key_b64": ml_pub_b64,
      "ml_public_key_pem": ml_pub_pem,
      "ml_algorithm": ML_ALG_DSA,
      "created_at": now.isoformat(),
    }
    return item


def _issue_ec_mtls_cert(common_name, organization, country="VN", state_or_province="HCM", locality="Q12", organizational_unit="GovPortal", subject_id=None, subject_type="identity", provided_public_key_pem=None):
  if not provided_public_key_pem:
    raise RuntimeError("EC mTLS certificate issuance requires a provided public key")
  _validate_ec_public_key(provided_public_key_pem)
  if not BROWSER_CLIENT_CA_KEY.exists() or not BROWSER_CLIENT_CA_CERT.exists():
    raise RuntimeError("Browser mTLS CA files are not mounted; cannot issue mTLS client certificate")
  now = datetime.now(timezone.utc)

  with tempfile.TemporaryDirectory() as tmpdir:
    tmpdir_path = Path(tmpdir)
    public_key_file = tmpdir_path / "client.pub.pem"
    temp_key_file = tmpdir_path / "csr.key.pem"
    csr_file = tmpdir_path / "client.csr"
    cert_file = tmpdir_path / "client.crt.pem"
    ext_file = tmpdir_path / "client_ext.cnf"
    public_key_file.write_text(provided_public_key_pem, encoding="utf-8")
    ext_file.write_text(
      "basicConstraints=CA:FALSE\n"
      "keyUsage=digitalSignature\n"
      "extendedKeyUsage=clientAuth\n",
      encoding="utf-8",
    )
    subj = (
      f"/C={country[:2].upper()}"
      f"/ST={state_or_province}"
      f"/L={locality}"
      f"/O={organization}"
      f"/OU={organizational_unit}"
      f"/CN={common_name}"
    )
    _run_openssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:secp384r1", "-out", str(temp_key_file)])
    _run_openssl(["req", "-new", "-key", str(temp_key_file), "-out", str(csr_file), "-subj", subj])
    _run_openssl([
      "x509", "-req",
      "-in", str(csr_file),
      "-CAkey", str(BROWSER_CLIENT_CA_KEY),
      "-CA", str(BROWSER_CLIENT_CA_CERT),
      "-CAcreateserial",
      "-force_pubkey", str(public_key_file),
      "-out", str(cert_file),
      "-days", "825",
      "-extfile", str(ext_file),
    ])
    cert_pem = cert_file.read_text(encoding="utf-8")
    cert_meta = _openssl_cert_metadata(cert_pem)

  cert_id = f"cert-{uuid.uuid4().hex[:12]}"
  return {
    "cert_id": cert_id,
    "officer_id": subject_id if subject_type == "officer" else None,
    "subject_id": subject_id,
    "subject_type": subject_type,
    "document_id": None,
    "purpose": "mtls_client",
    "serial": cert_meta["serial"],
    "subject": cert_meta["subject"],
    "issuer": cert_meta["issuer"],
    "not_before": cert_meta["not_before"],
    "not_after": cert_meta["not_after"],
    "certificate": cert_pem,
    "public_key_pem": provided_public_key_pem,
    "created_at": now.isoformat(),
  }

def _issue_identity_cert(common_name, organization, country="VN", state_or_province="HCM", locality="Q12", organizational_unit="CA Q12", officer_id=None, document_id=None, purpose="officer_identity", provided_public_key_pem=None, subject_type="identity", csr_pem=None):
  if purpose == "mtls_client":
    return _issue_ec_mtls_cert(
      common_name=common_name,
      organization=organization,
      country=country,
      state_or_province=state_or_province,
      locality=locality,
      organizational_unit=organizational_unit,
      subject_id=officer_id,
      subject_type=subject_type,
      provided_public_key_pem=provided_public_key_pem,
    )
  # Officer-issued certificates always use ML-DSA so the private key can sign documents directly.
  if purpose in ("officer_identity", "document_signing"):
    return _issue_ml_officer_cert(
      common_name=common_name,
      organization=organization,
      country=country,
      state_or_province=state_or_province,
      locality=locality,
      organizational_unit=organizational_unit,
      officer_id=officer_id,
      provided_public_key_pem=provided_public_key_pem,
      csr_pem=csr_pem,
    )
  return _issue_ml_officer_cert(
    common_name=common_name,
    organization=organization,
    country=country,
    state_or_province=state_or_province,
    locality=locality,
    organizational_unit=organizational_unit,
    officer_id=officer_id,
    provided_public_key_pem=provided_public_key_pem,
    csr_pem=csr_pem,
  )


def _latest_cert_for_officer(records, officer_id):
  if not officer_id:
    return None
  candidates = [r for r in records if r.get("officer_id") == officer_id]
  if not candidates:
    return None
  candidates.sort(key=lambda r: r.get("created_at") or "", reverse=True)
  return candidates[0]

def _officer_has_valid_cert(records, officer_id):
  """Check if officer already has an active (not expired) certificate"""
  if not officer_id:
    return False
  latest = _latest_cert_for_officer(records, officer_id)
  if not latest:
    return False
  # Check if certificate is still valid (not expired)
  try:
    not_after = datetime.fromisoformat(latest.get("not_after", ""))
    now = datetime.now(timezone.utc)
    return not_after > now
  except Exception:
    return False

def _latest_cert_for_document(records, document_id):
  if not document_id:
    return None
  candidates = [r for r in records if r.get("document_id") == document_id]
  if not candidates:
    return None
  candidates.sort(key=lambda r: r.get("created_at") or "", reverse=True)
  return candidates[0]

def generate_ml_keypair():
  if not _openssl_available():
    raise RuntimeError("OpenSSL binary not available to generate ML-DSA keys")
  with tempfile.TemporaryDirectory() as tmpdir:
    tmpdir_path = Path(tmpdir)
    priv_path = tmpdir_path / "ml_priv.pem"
    pub_path = tmpdir_path / "ml_pub.pem"
    _run_openssl(["genpkey", "-algorithm", ML_ALG_DSA, "-out", str(priv_path)])
    _run_openssl(["pkey", "-in", str(priv_path), "-pubout", "-out", str(pub_path)])
    priv_pem = priv_path.read_bytes()
    pub_pem = pub_path.read_bytes()
    write_bytes_file(MLDSA_PRIV_PEM, priv_pem)
    write_bytes_file(MLDSA_PUB_PEM, pub_pem)
    return pub_pem, priv_pem

def load_or_create_ml_keys():
  priv = read_bytes_file(*MLDSA_PRIV_CANDIDATES)
  pub = read_bytes_file(*MLDSA_PUB_CANDIDATES)
  if priv and pub:
    return pub, priv
  return generate_ml_keypair()

def sign_with_ml(message_bytes, private_key_pem=None):
  if not _openssl_available():
    raise RuntimeError("OpenSSL binary not available for ML-DSA signing")
  if not private_key_pem:
    raise RuntimeError("Server-side document signing is disabled; private key must stay on the client")
  sk = private_key_pem.encode('utf-8') if isinstance(private_key_pem, str) else private_key_pem
  with tempfile.TemporaryDirectory() as tmpdir:
    tmpdir_path = Path(tmpdir)
    priv_path = tmpdir_path / "ml_priv.pem"
    msg_path = tmpdir_path / "message.bin"
    sig_path = tmpdir_path / "signature.bin"
    priv_path.write_bytes(sk)
    msg_path.write_bytes(message_bytes)
    _run_openssl([
      "pkeyutl",
      "-sign",
      "-rawin",
      "-inkey", str(priv_path),
      "-in", str(msg_path),
      "-out", str(sig_path),
    ])
    sig = sig_path.read_bytes()
  return base64.b64encode(sig).decode('ascii')

def verify_with_ml(message_bytes, signature_b64, public_key_b64=None):
  if not _openssl_available():
    raise RuntimeError("OpenSSL binary not available for ML-DSA verification")
  signature = base64.b64decode(signature_b64)
  if public_key_b64:
    pub_pem = base64.b64decode(public_key_b64)
  else:
    raise RuntimeError("ML-DSA verification requires the signer's public key")
  with tempfile.TemporaryDirectory() as tmpdir:
    tmpdir_path = Path(tmpdir)
    pub_path = tmpdir_path / "ml_pub.pem"
    msg_path = tmpdir_path / "message.bin"
    sig_path = tmpdir_path / "signature.bin"
    pub_path.write_bytes(pub_pem)
    msg_path.write_bytes(message_bytes)
    sig_path.write_bytes(signature)
    try:
      _run_openssl([
        "pkeyutl",
        "-verify",
        "-rawin",
        "-pubin",
        "-inkey", str(pub_path),
        "-in", str(msg_path),
        "-sigfile", str(sig_path),
      ])
      return True
    except Exception:
      return False

def _generate_qr_code(officer_id, doc_id, signature, doc_hash):
    """Generates a QR code image containing the officer's certificate and document metadata."""
    try:
        records = _load_cert_store()
        officer_cert_info = _latest_cert_for_officer(records, officer_id)
        if not officer_cert_info:
            logger.warning(f"No certificate found for officer {officer_id} to generate QR code.")
            return None
        
        cert_pem = officer_cert_info['certificate']
        cert_pem_b64 = base64.b64encode(cert_pem.encode('utf-8')).decode('ascii')
        
        qr_metadata = {
            "doc_id": doc_id,
            "signed_at": datetime.now(timezone.utc).isoformat(),
            "signature": signature,
            "officer_id": officer_id,
            "doc_hash": doc_hash,
        }
        
        qr_payload = f"{cert_pem_b64}|{json.dumps(qr_metadata)}"
        
        img = qrcode.make(qr_payload)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        return base64.b64encode(buf.getvalue()).decode('ascii')
    except Exception as e:
        logger.error(f"Failed to generate QR code: {e}")
        return None

def _verify_certificate_chain(cert_pem_to_verify):
    """Verifies a PEM certificate against the service's root CA."""
    try:
        _, ca_cert_path = _ensure_business_ca_files()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            cert_to_verify_file = tmpdir_path / "cert.pem"
            
            cert_to_verify_file.write_text(cert_pem_to_verify)
            
            _run_openssl([
                "verify",
                "-CAfile", str(ca_cert_path),
                str(cert_to_verify_file)
            ])
        return True
    except Exception as e:
        logger.error(f"Certificate chain verification failed: {e}")
        return False

@app.route("/api/documents/sign", methods=["POST"])
def sign_document():
  return jsonify({
    "error": "server_side_signing_disabled",
    "message": "Application-server signing is disabled. Business signatures must be produced on the trusted device and uploaded as detached signatures.",
  }), 410


@app.route("/api/documents/verify", methods=["POST"])
def verify_document():
  try:
    data = request.get_json()
    doc_b64 = data["document_base64"]
    doc_bytes = base64.b64decode(doc_b64)
    doc_hash = hashlib.sha256(doc_bytes).hexdigest()

    sig = data.get("signature")
    public_key_b64 = data.get("public_key_b64") or data.get("pub_b64")
    if ML_ENABLED and _openssl_available() and data.get('signature_algorithm') == 'ML-DSA':
      valid = verify_with_ml(doc_bytes, sig, public_key_b64=public_key_b64)
    else:
      return jsonify({"error": "Only ML-DSA verification is supported"}), 400

    log_event("document_verified", {
      "doc_hash": doc_hash,
      "valid": str(valid).lower()
    })
    return jsonify({"valid": valid, "doc_hash": doc_hash,
                    "tampered": not valid}), 200 if valid else 400
  except Exception as e:
    logger.error(f"Document verification failed: {e}")
    return jsonify({"error": "Verification failed"}), 500

@app.route("/api/documents/verify-qr", methods=["POST"])
def verify_document_from_qr():
  try:
    data = request.get_json()
    qr_payload = data.get("qr_payload")
    document_base64 = data.get("document_base64") 

    if not qr_payload or not document_base64:
        return jsonify({"error": "qr_payload and document_base64 are required"}), 400

    # 1. Parse QR payload
    try:
        cert_pem_b64, metadata_json = qr_payload.split('|', 1)
        cert_pem = base64.b64decode(cert_pem_b64).decode('utf-8')
        metadata = json.loads(metadata_json)
        signature_b64 = metadata['signature']
        doc_bytes = base64.b64decode(document_base64)
    except Exception as e:
        return jsonify({"valid": False, "error": "Invalid QR payload format", "details": str(e)}), 400

    # 2. Load and check officer's certificate
    try:
        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
    except Exception as e:
        return jsonify({"valid": False, "error": "Invalid certificate in QR payload", "details": str(e)}), 400

    # 3. Check certificate expiry
    if datetime.now(timezone.utc) > cert_obj.not_valid_after_utc:
        return jsonify({
            "valid": False, 
            "status": "expired",
            "error": "Tài liệu đã hết hạn, vui lòng nộp và yêu cầu ký lại",
            "details": f"Certificate expired on {cert_obj.not_valid_after_utc.isoformat()}"
        }), 400
    
    # 4. Verify certificate against Root CA
    if not _verify_certificate_chain(cert_pem):
         return jsonify({"valid": False, "error": "Certificate is not trusted by this PKI"}), 400

    # 5. Extract public key from certificate
    public_key = cert_obj.public_key()
    public_key_pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_b64_for_verify = base64.b64encode(public_key_pem_bytes).decode('ascii')

    # 6. Verify document signature
    is_signature_valid = verify_with_ml(
        message_bytes=doc_bytes, 
        signature_b64=signature_b64, 
        public_key_b64=public_key_b64_for_verify
    )

    if not is_signature_valid:
        return jsonify({"valid": False, "error": "Signature verification failed. Document may have been tampered with."}), 400

    # 7. If everything is valid, return success and document info
    return jsonify({
        "valid": True,
        "status": "valid",
        "document_info": {
            "id": metadata.get("doc_id"),
            "signed_at": metadata.get("signed_at"),
            "officer_id": metadata.get("officer_id"),
            "doc_hash": metadata.get("doc_hash"),
        },
        "certificate_info": {
            "subject": cert_obj.subject.rfc4514_string(),
            "issuer": cert_obj.issuer.rfc4514_string(),
            "expires_at": cert_obj.not_valid_after_utc.isoformat(),
        }
    }), 200
  except Exception as e:
      logger.error(f"QR verification failed: {e}")
      return jsonify({"error": "QR verification failed", "details": str(e)}), 500

@app.route("/api/pki/generate-qr", methods=["POST"])
def generate_qr_endpoint():
    """Generates a QR code for an already signed document."""
    try:
        data = request.get_json()
        officer_id = data.get("officer_id")
        doc_id = data.get("doc_id")
        signature = data.get("signature")
        doc_hash = data.get("doc_hash")

        if not all([officer_id, doc_id, signature, doc_hash]):
            return jsonify({"error": "Missing required fields for QR generation (officer_id, doc_id, signature, doc_hash)"}), 400

        qr_image_b64 = _generate_qr_code(officer_id, doc_id, signature, doc_hash)

        if not qr_image_b64:
            return jsonify({"error": "Failed to generate QR code"}), 500

        return jsonify({"qr_image_base64": qr_image_b64}), 200
    except Exception as e:
        logger.error(f"QR generation endpoint failed: {e}")
        return jsonify({"error": "QR generation failed"}), 500


@app.route("/health")
def health():
  try:
    return jsonify({"status": "ok", "ml_enabled": ML_ENABLED, "ml_lib": _openssl_available()}), 200
  except Exception:
    return jsonify({"status": "error"}), 500

@app.route("/.well-known/ca.pem", methods=["GET"])
def ca_certificate():
  try:
    # Serve the PKI root CA certificate in PEM form for traditional PKI clients.
    if os.path.exists(PKI_CA_CERT):
      with open(PKI_CA_CERT, 'r', encoding='utf-8') as f:
        pem = f.read()
      return app.response_class(pem, mimetype='application/pem-certificate-chain'), 200, {"Cache-Control": "public, max-age=3600"}
    return jsonify({"error": "CA certificate not available"}), 500
  except Exception as e:
    logger.error(f"CA certificate lookup failed: {e}")
    return jsonify({"error": "CA certificate lookup failed"}), 500

@app.route("/api/pki/public-key", methods=["GET"])
def public_key():
  try:
    _ensure_business_ca_files()
    if not PKI_CA_PUBLIC.exists():
      _run_openssl(["pkey", "-in", str(PKI_CA_KEY), "-pubout", "-out", str(PKI_CA_PUBLIC)])
    return app.response_class(PKI_CA_PUBLIC.read_text(encoding="utf-8"), mimetype='text/plain'), 200
  except Exception as e:
    logger.error(f"Public key lookup failed: {e}")
    return jsonify({"error": "public key lookup failed"}), 500


@app.route("/api/pki/issue-certificate", methods=["POST"])
def issue_certificate():
  try:
    data = request.get_json(force=True) or {}
    common_name = (data.get("common_name") or data.get("cn") or "officer.local").strip()
    organization = (data.get("organization") or data.get("org") or PKI_SUBJECT_O).strip()
    country = (data.get("country") or PKI_SUBJECT_C).strip()
    state_or_province = (data.get("st") or data.get("state") or data.get("state_or_province") or PKI_SUBJECT_ST).strip()
    locality = (data.get("l") or data.get("locality") or PKI_SUBJECT_L).strip()
    organizational_unit = (data.get("ou") or data.get("organizational_unit") or PKI_SUBJECT_OU).strip()
    subject_type = (data.get("subject_type") or ("officer" if data.get("officer_id") else "identity")).strip()
    subject_id = (data.get("subject_id") or data.get("officer_id") or "").strip() or None
    officer_id = subject_id
    # PKI issues identity certificates for portal users. Ignore document-related parameters supplied by callers.
    document_id = None
    cert_profile = (data.get("cert_profile") or "").strip()
    purpose = "mtls_client" if cert_profile == "mtls_client" else f"{subject_type}_identity"
    public_key_pem = (data.get("public_key_pem") or "").strip() or None
    csr_pem = (data.get("csr_pem") or data.get("csr") or "").strip() or None
    allow_reissue = bool(data.get("allow_reissue", False))
    
    if not common_name:
      return jsonify({"error": "common_name is required"}), 400
    if public_key_pem:
      try:
        if purpose == "mtls_client":
          _validate_ec_public_key(public_key_pem)
        else:
          _validate_ml_dsa_public_key(public_key_pem)
      except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    elif csr_pem and purpose != "mtls_client":
      public_key_pem = None
    elif subject_type == "officer" and officer_id:
      public_key_pem = _load_current_officer_public_key_from_storage(officer_id)
    else:
      return jsonify({"error": "csr_pem, public_key_pem, or officer_id is required"}), 400

    # Check 1-certificate-per-officer constraint for officer certificates
    if subject_type == "officer" and officer_id and not allow_reissue:
      records = _load_cert_store()
      if _officer_has_valid_cert(records, officer_id):
        return jsonify({
          "error": "Officer already has an active certificate",
          "officer_id": officer_id,
          "message": "Request key renewal if certificate is lost"
        }), 409

    item = _issue_identity_cert(
      common_name=common_name,
      organization=organization,
      country=country,
      state_or_province=state_or_province,
      locality=locality,
      organizational_unit=organizational_unit,
      officer_id=officer_id,
      document_id=None,
      purpose=purpose,
      provided_public_key_pem=public_key_pem,
      subject_type=subject_type,
      csr_pem=csr_pem,
    )
    records = _load_cert_store()
    records.insert(0, item)
    _save_cert_store(records)
    # Legacy registration with storage service for officer signing checks.
    if subject_type == "officer" and officer_id:
      try:
        reg_payload = {
          "cert_id": item["cert_id"],
          "certificate": item["certificate"],
          "not_after": item["not_after"]
        }
        headers = {"Content-Type": "application/json"}
        reg_response = requests.post(
          f"{storage_service_url}/api/storage/officers/{officer_id}/certificates",
          json=reg_payload,
          headers=headers,
          timeout=10
        )
        if reg_response.status_code not in [201, 200]:
          logger.warning(f"Failed to register cert with storage service: {reg_response.status_code}")
      except Exception as e:
        logger.warning(f"Storage service registration failed: {e}")

    return jsonify({
      "cert_id": item["cert_id"],
      "issuer": item["issuer"],
      "subject": item["subject"],
      "certificate": item["certificate"],
      "officer_id": item.get("officer_id"),
      "subject_type": subject_type,
      "subject_id": subject_id,
      "document_id": item.get("document_id"),
      "purpose": item.get("purpose"),
      "public_key_pem": item["public_key_pem"],
      "not_before": item["not_before"],
      "not_after": item["not_after"],
    }), 201
  except Exception as e:
    logger.error(f"Issue certificate failed: {e}")
    return jsonify({"error": "issue certificate failed"}), 500


@app.route("/api/pki/certificates", methods=["GET"])
def list_certificates():
  try:
    records = _load_cert_store()
    officer_id = request.args.get("officer_id", "").strip()
    document_id = request.args.get("document_id", "").strip()
    if officer_id:
      records = [r for r in records if r.get("officer_id") == officer_id]
    if document_id:
      records = [r for r in records if r.get("document_id") == document_id]

    # Keep payload light in list endpoint
    view = [
      {
        "cert_id": r.get("cert_id"),
        "officer_id": r.get("officer_id"),
        "document_id": r.get("document_id"),
        "purpose": r.get("purpose"),
        "serial": r.get("serial"),
        "issuer": r.get("issuer"),
        "subject": r.get("subject"),
        "not_before": r.get("not_before"),
        "not_after": r.get("not_after"),
        "created_at": r.get("created_at"),
      }
      for r in records
    ]
    return jsonify({"count": len(view), "certificates": view}), 200
  except Exception as e:
    logger.error(f"List certificates failed: {e}")
    return jsonify({"error": "list certificates failed"}), 500


@app.route("/api/pki/certificates/<cert_id>", methods=["GET"])
def get_certificate(cert_id):
    try:
        records = _load_cert_store() 
        logger.info(f"Đang tìm kiếm cert_id: {cert_id}. Tổng số cert trong store: {len(records)}")
        
        for r in records:
            if r.get("cert_id") == cert_id:
                return app.response_class(r.get("certificate", ""), mimetype='text/plain'), 200
                
        return jsonify({"error": "certificate not found"}), 404
    except Exception as e:
        logger.error(f"Get certificate failed: {e}")
        return jsonify({"error": "get certificate failed"}), 500

@app.route("/api/pki/certificates/officer/<officer_id>/latest", methods=["GET"])
def get_latest_officer_certificate(officer_id):
  try:
    records = _load_cert_store()
    latest = _latest_cert_for_officer(records, officer_id)
    if not latest:
      return jsonify({"error": "certificate not found", "officer_id": officer_id}), 404
    return jsonify({
      "officer_id": officer_id,
      "cert_id": latest.get("cert_id"),
      "document_id": latest.get("document_id"),
      "purpose": latest.get("purpose"),
      "issuer": latest.get("issuer"),
      "subject": latest.get("subject"),
      "not_before": latest.get("not_before"),
      "not_after": latest.get("not_after"),
      "certificate": latest.get("certificate"),
    }), 200
  except Exception as e:
    logger.error(f"Get latest officer certificate failed: {e}")
    return jsonify({"error": "get latest officer certificate failed"}), 500


@app.route("/api/pki/certificates/by-document/<doc_id>", methods=["GET"])
def get_certificate_by_document(doc_id):
  try:
    records = _load_cert_store()
    matched = [r for r in records if r.get("document_id") == doc_id]
    if not matched:
      officer_id = request.args.get("officer_id", "").strip()
      latest = _latest_cert_for_officer(records, officer_id)
      if not latest:
        return jsonify({"error": "certificate not found for document", "document_id": doc_id}), 404
      matched = [latest]

    matched.sort(key=lambda r: r.get("created_at") or "", reverse=True)
    item = matched[0]
    return jsonify({
      "document_id": doc_id,
      "cert_id": item.get("cert_id"),
      "officer_id": item.get("officer_id"),
      "purpose": item.get("purpose"),
      "issuer": item.get("issuer"),
      "subject": item.get("subject"),
      "not_before": item.get("not_before"),
      "not_after": item.get("not_after"),
      "certificate": item.get("certificate"),
    }), 200
  except Exception as e:
    logger.error(f"Get certificate by document failed: {e}")
    return jsonify({"error": "get certificate by document failed"}), 500

if __name__ == "__main__":
  ensure_state_dirs()
  try:
    _load_or_create_ca()
  except Exception as e:
    logger.warning(f"Failed to initialize local PKI CA: {e}")
  app.run(host="0.0.0.0", port=5000, debug=False)
