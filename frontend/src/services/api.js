const API_BASE = (import.meta.env && import.meta.env.VITE_API_BASE_URL) || 'http://127.0.0.1:8000';

export function getToken() {
  const token = localStorage.getItem('kavach_token');
  if (!token) return null;
  return token.replace(/^"|"$/g, '').trim();
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

  let customHeaders = {};
  if (options.headers instanceof Headers) {
    options.headers.forEach((val, key) => {
      customHeaders[key] = val;
    });
  } else if (options.headers && typeof options.headers === 'object') {
    customHeaders = options.headers;
  }

  const headers = {
    ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
    ...customHeaders,
  };

  const token = getToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const config = {
    ...options,
    headers,
  };

  // For POST/PUT/PATCH with no body and Content-Type application/json, provide empty JSON object
  if (
    !isFormData &&
    config.headers['Content-Type'] === 'application/json' &&
    ['POST', 'PUT', 'PATCH'].includes((config.method || '').toUpperCase()) &&
    config.body === undefined
  ) {
    config.body = JSON.stringify({});
  }

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
  getThreatLocations: (scanId) => request(`/security/threat-locations/${scanId}`),

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

  // User Incident Reports (User role)
  getUserReports: () => request('/security/reports'),
  getUserReportDetail: (reportId) => request(`/security/reports/${reportId}`),
  downloadUserReportPdf: (reportId) => `${API_BASE}/security/reports/${reportId}/download`,

  // Guardian Incident Reports (Guardian role)
  getGuardianReports: () => request('/guardian/reports'),
  getGuardianReportDetail: (reportId) => request(`/guardian/reports/${reportId}`),
  downloadGuardianReportPdf: (reportId) => `${API_BASE}/guardian/reports/${reportId}/download`,

  // KAVACH AI Assistant (User & Guardian)
  chatWithAI: (body) => request('/ai/chat', { method: 'POST', body: JSON.stringify(body) }),
};
