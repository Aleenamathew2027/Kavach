const API_BASE = 'http://127.0.0.1:8000';

export function getToken() {
  return localStorage.getItem('kavach_token');
}

export function getRole() {
  return localStorage.getItem('kavach_role') || 'user';
}

export function setAuth({ token, role }) {
  localStorage.setItem('kavach_token', token);
  localStorage.setItem('kavach_role', role);
  localStorage.setItem('kavach_logged_in', 'true');
}

export function clearAuth() {
  localStorage.removeItem('kavach_token');
  localStorage.removeItem('kavach_role');
  localStorage.removeItem('kavach_logged_in');
}

export function isAuthenticated() {
  return !!getToken();
}

async function request(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const isFormData = options.body instanceof FormData;
  const headers = {
    ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
    ...(options.headers || {}),
  };

  const token = getToken();
  if (token && !headers.Authorization) {
    headers.Authorization = `Bearer ${token}`;
  }

  const config = {
    ...options,
    headers,
  };

  try {
    const response = await fetch(url, config);
    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      let errorMessage = 'An error occurred. Please try again.';
      if (typeof data.detail === 'string') {
        errorMessage = data.detail;
      } else if (Array.isArray(data.detail)) {
        errorMessage = data.detail.map((d) => d.msg || JSON.stringify(d)).join(', ');
      }
      const error = new Error(errorMessage);
      error.status = response.status;
      error.data = data;
      throw error;
    }

    return data;
  } catch (err) {
    if (err.status) throw err;
    const networkErr = new Error('Cannot connect to KAVACH backend server. Please make sure FastAPI is running on http://127.0.0.1:8000.');
    networkErr.status = 0;
    networkErr.isNetwork = true;
    throw networkErr;
  }
}

export const api = {
  // Authentication
  register: (body) => request('/users/register', { method: 'POST', body: JSON.stringify(body) }),
  login: (body) => request('/users/login', { method: 'POST', body: JSON.stringify(body) }),
  googleLogin: (body) => request('/users/google-login', { method: 'POST', body: JSON.stringify(body) }),
  verifyGuardianCode: (body) => request('/guardian/verify-code', { method: 'POST', body: JSON.stringify(body) }),

  // User details & profile management
  getMe: () => request('/users/me'),
  updateProfile: (body) => request('/users/me', { method: 'PUT', body: JSON.stringify(body) }),
  changePassword: (body) => request('/users/change-password', { method: 'POST', body: JSON.stringify(body) }),

  // Security Scanners & Alerts (User role)
  analyzeMessage: (body) => request('/security/analyze-message', { method: 'POST', body: JSON.stringify(body) }),
  analyzeLink: (body) => request('/security/analyze-link', { method: 'POST', body: JSON.stringify(body) }),
  analyzeDocument: (formData) => request('/security/analyze-document', { method: 'POST', body: formData }),
  getSecurityAlerts: () => request('/security/alerts'),
  markAlertRead: (id) => request(`/security/alerts/${id}/read`, { method: 'PATCH' }),
  getSecuritySummary: () => request('/security/summary'),

  // Role Dashboards & Management
  getUserDashboard: () => request('/user/dashboard'),
  getAdminDashboard: () => request('/admin/dashboard'),
  getAdminUsers: () => request('/admin/users'),
  getAdminSecurityEvents: () => request('/admin/security-events'),
  getAdminGuardians: () => request('/admin/guardians'),
  getAdminReports: () => request('/admin/reports'),
  getAdminActivity: () => request('/admin/activity'),
  getGuardianDashboard: () => request('/guardian/dashboard'),
  getGuardianAlerts: () => request('/guardian/alerts'),
  markGuardianAlertRead: (id) => request(`/guardian/alerts/${id}/read`, { method: 'PATCH' }),
  getGuardianActivity: () => request('/guardian/activity'),

  // Guardian Code Management (User role)
  generateGuardianCode: () => request('/guardian/generate-code', { method: 'POST' }),
  revokeGuardianCode: () => request('/guardian/revoke-code', { method: 'POST' }),
};
