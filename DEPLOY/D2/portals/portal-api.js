/** Shared API client for all GovPortal HTML portals (ports 3000–3004 → gateway 8080). */
const API_URL = `${window.location.protocol}//${window.location.hostname}:8080`;

function getSessionToken() {
  return localStorage.getItem('sessionId');
}

function buildAuthHeaders(includeJson = true) {
  const headers = {};
  if (includeJson) headers['Content-Type'] = 'application/json';
  const token = getSessionToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function apiFetch(path, options = {}) {
  const headers = { ...buildAuthHeaders(options.body != null), ...(options.headers || {}) };
  const init = {
    method: options.method || 'GET',
    mode: 'cors',
    credentials: 'omit',
    headers,
  };
  if (options.body != null) {
    init.body = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
  }
  return fetch(`${API_URL}${path}`, init);
}

async function parseJsonResponse(response) {
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const err = new Error(data.error || `HTTP ${response.status}`);
    err.status = response.status;
    err.data = data;
    throw err;
  }
  return data;
}

function saveSession(data, username, displayName) {
  const token = data.token || data.session_id;
  if (!token) return null;
  localStorage.setItem('sessionId', token);
  localStorage.setItem('user_id', data.user_id || username);
  if (data.user_type) localStorage.setItem('user_type', data.user_type);
  if (displayName) localStorage.setItem('display_name', displayName);
  if (data.token_alg) localStorage.setItem('token_alg', data.token_alg);
  return token;
}

function clearSession() {
  localStorage.removeItem('sessionId');
  localStorage.removeItem('user_id');
  localStorage.removeItem('user_type');
  localStorage.removeItem('display_name');
  localStorage.removeItem('token_alg');
}
