import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json'
  }
});

// Request interceptor to attach JWT
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor to handle 401
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      const currentPath = window.location.pathname;
      if (currentPath !== '/login') {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

// Auth API
export const authApi = {
  login: (data) => api.post('/auth/login', data),
  register: (data) => api.post('/auth/register', data),
  getMe: () => api.get('/auth/me')
};

// Logs API
export const logsApi = {
  upload: (formData) => api.post('/logs/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  }),
  parsePreview: (data) => api.post('/logs/parse-preview', data),
  getFiles: () => api.get('/logs/files'),
  getFileById: (id) => api.get(`/logs/files/${id}`),
  getRawContent: (id) => api.get(`/logs/files/${id}/raw`),
  downloadFile: (id) => api.get(`/logs/files/${id}/download`, { responseType: 'blob' }),
  deleteFile: (id, purgeEvents = true) => api.delete(`/logs/files/${id}?purgeEvents=${purgeEvents}`),
  deleteFileByName: (fileName) => api.delete(`/logs/by-name/${encodeURIComponent(fileName)}`),
  resetAll: () => api.post('/logs/reset-all')
};

// Events API
export const eventsApi = {
  getEvents: (params) => api.get('/events', { params }),
  getEventById: (id) => api.get(`/events/${id}`)
};

// Rules API
export const rulesApi = {
  getRules: () => api.get('/rules'),
  getRuleById: (id) => api.get(`/rules/${id}`),
  createRule: (data) => api.post('/rules', data),
  updateRule: (id, data) => api.patch(`/rules/${id}`, data),
  deleteRule: (id) => api.delete(`/rules/${id}`),
  runAll: () => api.post('/rules/run-all')
};

// Alerts API
export const alertsApi = {
  getAlerts: (params) => api.get('/alerts', { params }),
  getAlertById: (id) => api.get(`/alerts/${id}`),
  updateAlert: (id, data) => api.patch(`/alerts/${id}`, data),
  assignEndpoints: (id) => api.post(`/alerts/${id}/assign-endpoint-profiles`),
  createCase: (id, data) => api.post(`/alerts/${id}/create-case`, data)
};

// Cases API
export const casesApi = {
  getCases: (params) => api.get('/cases', { params }),
  getCaseById: (id) => api.get(`/cases/${id}`),
  createCase: (data) => api.post('/cases', data),
  updateCase: (id, data) => api.patch(`/cases/${id}`, data),
  deleteCase: (id) => api.delete(`/cases/${id}`),
  addEvents: (id, data) => api.post(`/cases/${id}/add-events`, data),
  removeEvent: (id, eventId) => api.delete(`/cases/${id}/events/${eventId}`),
  getEvidence: (id) => api.get(`/cases/${id}/evidence`),
  addEvidence: (id, formData) => api.post(`/cases/${id}/evidence`, formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  }),
  validateEvidence: (id, evidenceId, data) => api.patch(`/cases/${id}/evidence/${evidenceId}/validate`, data)
};

// IOCs API
export const iocsApi = {
  getIOCs: (params) => api.get('/iocs', { params }),
  createIOC: (data) => api.post('/iocs', data),
  updateIOC: (id, data) => api.patch(`/iocs/${id}`, data),
  deleteIOC: (id) => api.delete(`/iocs/${id}`),
  lookup: (data) => api.post('/iocs/lookup', data),
  executeSql: (query) => api.post('/iocs/sql', { query }),
  generateAiQuery: (data) => api.post('/iocs/ai/generate', data),
  getAiSchema: () => api.get('/iocs/ai/schema'),
  getAiHistory: () => api.get('/iocs/ai/history')
};

// Endpoints API
export const endpointsApi = {
  getEndpoints: (params) => api.get('/endpoints', { params }),
  getEndpointById: (id) => api.get(`/endpoints/${id}`),
  updateEndpoint: (id, data) => api.patch(`/endpoints/${id}`, data)
};

// Accounts API
export const accountsApi = {
  getAccounts: (params) => api.get('/accounts', { params }),
  getAccountById: (id) => api.get(`/accounts/${id}`),
  updateAccount: (id, data) => api.patch(`/accounts/${id}`, data)
};

// Timeline API
export const timelineApi = {
  getTimeline: (caseId, params) => api.get(`/timeline/case/${caseId}`, { params }),
  addEntry: (caseId, data) => api.post(`/timeline/case/${caseId}`, data),
  deleteEntry: (id) => api.delete(`/timeline/${id}`)
};

// Attack Chain API
export const attackChainApi = {
  getAttackChain: (caseId) => api.get(`/attack-chain/case/${caseId}`),
  updateAttackChain: (caseId, data) => api.patch(`/attack-chain/case/${caseId}`, data)
};

// Impact Assessment API
export const impactApi = {
  getImpact: (caseId) => api.get(`/impact/case/${caseId}`),
  updateImpact: (caseId, data) => api.put(`/impact/case/${caseId}`, data)
};

// Review API
export const reviewApi = {
  getReview: (caseId) => api.get(`/review/case/${caseId}`),
  saveReview: (caseId, data) => api.post(`/review/case/${caseId}`, data)
};

// Reports API
export const reportsApi = {
  getAllReports: () => api.get('/reports'),
  getReport: (caseId) => api.get(`/reports/case/${caseId}`),
  generateReport: (caseId) => api.post(`/reports/case/${caseId}/generate`),
  exportReport: (caseId, format = 'md') => api.get(`/reports/case/${caseId}/export?format=${format}`, {
    responseType: 'blob'
  })
};

// Dashboard API
export const dashboardApi = {
  getSummary: (params) => api.get('/dashboard/summary', { params })
};

export default api;
