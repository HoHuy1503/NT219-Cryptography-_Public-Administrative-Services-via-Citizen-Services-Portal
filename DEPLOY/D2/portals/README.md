# GovPortal Multi-Role Web Interfaces

Web interfaces for all stakeholder roles in the government services portal system. Each role has its own dedicated portal running on localhost with a different port.

## Quick Start

### Prerequisites
- Python 3.6+
- Backend APIs running at `http://localhost:8080` (DMZ Gateway)

### Start All Portals
```bash
cd DEPLOY/D2/portals
./start_portals.sh
# or
python3 start_portals.py
```

All portals will start automatically on different ports.

## Available Portals

### 1. Citizen Portal (Port 3000)
**URL:** http://localhost:3000

**Features:**
- Scan QR codes on physical documents/certificates
- View list of accessed documents
- Manage personal profile
- Check document metadata
- User login/registration

**Use Cases:**
- Citizens scan government-issued documents with embedded QR codes
- Access services that verify their identity or credentials
- Track QR scanning history

**Example Actions:**
```bash
# In Citizen Portal:
1. Click "Quét QR" (Scan QR)
2. Paste QR payload: key(b64)|document_id|type|data|metadata
3. View decrypted document and metadata
4. Click "Tài Liệu Của Tôi" to see all accessed documents
```

---

### 2. Officer Portal (Port 3001)
**URL:** http://localhost:3001

**Features:**
- Create and manage user accounts (CITIZEN, OFFICER, ADMIN, AUDITOR, THIRD_PARTY roles)
- Sign documents with ML-DSA keys
- Manage public keys
- Rotate officer-specific encryption keys

**Use Cases:**
- Government officers/staff create accounts for citizens
- Officers sign official documents for storage
- Manage digital signatures and key lifecycle
- View key rotation schedule

**Example Actions:**
```bash
# In Officer Portal:
1. Click "Quản Lý Người Dùng" (Manage Users)
2. Create new account: citizen_001, password, role=CITIZEN
3. Click "Ký Tài Liệu" (Sign Document)
4. Upload/paste document content and sign it
5. Check key rotation status
```

---

### 3. Storage Admin Portal (Port 3002)
**URL:** http://localhost:3002

**Features:**
- View all stored document QRs
- List all registered users
- Review audit logs
- Filter documents by type
- Track access patterns

**Use Cases:**
- Storage administrators monitor system activity
- Compliance officers review audit trails
- System administrators manage user accounts
- Track document access for security

**Example Actions:**
```bash
# In Storage Admin Portal:
1. Dashboard shows stats (total documents, users, QR scans)
2. Click "Tài Liệu" (Documents) to see all document QRs
3. Click "Người Dùng" (Users) to manage accounts
4. Click "Kiểm Toán" (Audit) to review access logs
5. Filter documents by type (certificate, permit, license)
```

---

### 4. PKI Admin Portal (Port 3003)
**URL:** http://localhost:3003

**Features:**
- Issue digital certificates (X.509)
- Manage public key infrastructure
- Schedule and monitor key rotation
- View certificate validity periods
- Manage ECDH P-256 keys

**Use Cases:**
- PKI administrators issue certificates
- System manages cryptographic keys for officers and services
- Automatic key rotation scheduling
- Certificate lifecycle management

**Example Actions:**
```bash
# In PKI Admin Portal:
1. Click "Chứng Chỉ" (Certificates)
2. Create certificate with CN, organization, country
3. View list of active certificates
4. Click "Xoay Khóa" (Key Rotation)
5. Schedule rotation for officer accounts
```

---

### 5. Third-Party Portal (Port 3004)
**URL:** http://localhost:3004

**Features:**
- Submit access requests to citizen data
- Track request status (PENDING, APPROVED, DENIED)
- View documents shared with the organization
- Manage cross-organization data sharing
- Add contact information for data sharing

**Use Cases:**
- Third-party organizations request data from citizens
- Organizations like banks, insurance companies need verification
- Cross-agency document sharing workflows
- Integration with third-party services

**Example Actions:**
```bash
# In Third-party Portal:
1. Click "Yêu Cầu Truy Cập" (Request Access)
2. Enter: Organization name, email, citizen ID, document type, reason
3. Submit request
4. Click "Yêu Cầu Của Tôi" to track approval status
5. Access approved documents
```

---

## API Integration

All portals connect to backend APIs through the DMZ Gateway at:
```
http://localhost:8080
```

### Common API Endpoints Used:
- **Document QR:** `/api/qr/verify-document`, `/api/qr/document-qr`
- **Storage:** `/api/storage/users`, `/api/storage/documents`, `/api/storage/document-qr`
- **Users:** `/api/storage/login`, `/api/storage/users`
- **Keys:** `/api/storage/users/{user_id}/keys`
- **Audit:** `/api/storage/audit-log`

## Portal Features

### Common UI Elements:
- **Navigation bar:** Quick access to main sections
- **Dashboard:** Overview and statistics
- **Forms:** Input validation and error handling
- **Tables:** List views with sorting
- **Status badges:** Visual indicators (PENDING, APPROVED, DENIED)
- **Result messages:** Success/error notifications

### Security Features:
- Session-based authentication
- localStorage for session persistence
- CORS headers for API calls
- No sensitive data stored in HTML/JS
- All crypto operations on backend

## Development & Customization

### Adding a New Portal:
1. Create HTML file (e.g., `new-role.html`)
2. Add port mapping in `start_portals.py`:
```python
PORTALS = {
    # ... existing portals ...
    3005: ("new-role.html", "New Role Portal"),
}
```
3. Restart server

### Modifying API Endpoints:
- Update `API_URL` variable in portal HTML
- Change from `http://localhost:8080` to your backend URL
- Ensure CORS headers are set on backend

### Styling:
- All portals use inline CSS for easy customization
- Color schemes:
  - Citizen: Blue (#1e3c72, #2a5298)
  - Officer: Red/Orange (#c53030, #d69e2e)
  - Storage: Teal (#00838f, #00695c)
  - PKI: Purple (#6f42c1, #5a32a3)
  - Third-party: Orange (#e67e22, #d35400)

## Troubleshooting

### Portals won't start:
```bash
# Check if ports are already in use
lsof -i :3000
lsof -i :3001 # ... etc

# Use different ports - modify start_portals.py
```

### API calls fail:
- Ensure backend is running at `http://localhost:8080`
- Check browser console (F12) for CORS errors
- Verify backend APIs are returning correct responses

### Session not persisting:
- Clear browser localStorage: `localStorage.clear()`
- Re-login and check localStorage for `sessionId`

## Production Deployment

For production, instead of local Python server:
1. Use production web server (nginx, Apache)
2. Serve from `/var/www/govportal/portals/`
3. Configure reverse proxy for backend APIs
4. Enable TLS/HTTPS
5. Set Security headers (CSP, HSTS, etc.)

## Testing Workflow

```bash
# 1. Start backend services
cd DEPLOY/D2
vagrant up --provision
ansible-playbook -i playbook/inventory/hosts.yml playbook/site.yml

# 2. Initialize test data
./scripts/init_admin_accounts.sh
./scripts/init_qr_users.sh

# 3. Start portals
cd portals
./start_portals.sh

# 4. Test each portal
# Citizen: http://localhost:3000
# Officer: http://localhost:3001
# ... etc

# 5. Example workflow:
# - Officer creates citizen account (port 3001)
# - Officer generates document QR (CLI)
# - Citizen scans QR and accesses document (port 3000)
# - Storage admin reviews activity (port 3002)
# - PKI admin manages keys (port 3003)
# - Third-party requests access (port 3004)
```

## Architecture

```
┌─────────────────────────────────────────┐
│     Browser (localhost)                 │
├──────┬──────┬──────┬──────┬──────┬──────┤
│ 3000 │ 3001 │ 3002 │ 3003 │ 3004 │ ...  │
│Citz. │Off.  │Stor. │ PKI  │ 3rd  │ Dev  │
└───┬──┴──┬───┴──┬───┴──┬───┴──┬───┴──────┘
    │     │      │      │      │
    └─────┼───┬──┤      │      │
          │   │  │      │      │
     ┌────┴───┴──┴──────┴──────┴────────┐
     │  DMZ Gateway (localhost:8080)    │
     │  (Reverse Proxy to D2 Services)  │
     └────┬───────────────────────────┬─┘
          │                           │
    ┌─────┴─────┐          ┌──────────┴────┐
    │   D2      │          │   Storage     │
    │ Services  │──────────│   (Postgres)  │
    │ (Docker)  │          │   (Redis)     │
    └───────────┘          └───────────────┘
```

## Files

- `citizen.html` - Citizen portal interface
- `officer.html` - Officer management portal
- `storage.html` - Storage admin dashboard
- `pki.html` - PKI administration portal
- `thirdparty.html` - Third-party access portal
- `start_portals.py` - Multi-threaded HTTP server launcher
- `start_portals.sh` - Shell script wrapper
- `README.md` - This file

## License

Government Services Portal - Multi-Role Portal System
