import { getToken } from './api';

const API_BASE = (import.meta.env && import.meta.env.VITE_API_BASE_URL) || 'http://127.0.0.1:8000';

async function chatRequest(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const isFormData = options.body instanceof FormData;

  const headers = {
    ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
    ...(options.headers || {}),
  };

  const token = getToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const config = {
    ...options,
    headers,
  };

  const response = await fetch(url, config);
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    let msg = 'Guardian communication request failed.';
    if (typeof data.detail === 'string') msg = data.detail;
    else if (Array.isArray(data.detail)) msg = data.detail.map((d) => d.msg || JSON.stringify(d)).join(', ');
    const err = new Error(msg);
    err.status = response.status;
    throw err;
  }
  return data;
}

export const guardianChatService = {
  // Conversation metadata
  getConversation: () =>
    chatRequest('/guardian-chat/conversations', {
      method: 'GET',
    }),

  // Message listing
  getMessages: (conversationId) =>
    chatRequest(`/guardian-chat/conversations/${conversationId}/messages`, {
      method: 'GET',
    }),

  // Send normal text message
  sendTextMessage: (conversationId, text) =>
    chatRequest(`/guardian-chat/conversations/${conversationId}/messages`, {
      method: 'POST',
      body: JSON.stringify({ text }),
    }),

  // Upload and send recorded voice note
  sendVoiceMessage: async (conversationId, audioBlob, duration) => {
    const formData = new FormData();
    formData.append('file', audioBlob, 'voice_message.webm');
    if (duration !== undefined && duration !== null) {
      formData.append('duration', String(duration));
    }

    return chatRequest(`/guardian-chat/conversations/${conversationId}/voice`, {
      method: 'POST',
      body: formData,
    });
  },

  // Secure URL for voice audio streaming
  getVoiceUrl: (messageId) => `${API_BASE}/guardian-chat/messages/${messageId}/voice`,

  // Fetch voice audio blob with auth token
  fetchVoiceBlob: async (messageId) => {
    const url = `${API_BASE}/guardian-chat/messages/${messageId}/voice`;
    const token = getToken();
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    const res = await fetch(url, { headers });
    if (!res.ok) throw new Error('Unable to load voice audio');
    return res.blob();
  },

  // Mark message as read
  markMessageRead: (messageId) =>
    chatRequest(`/guardian-chat/messages/${messageId}/read`, {
      method: 'PATCH',
    }),

  // SMS & Notification Settings
  getSettings: () =>
    chatRequest('/guardian-chat/settings', {
      method: 'GET',
    }),

  updateSettings: (settings) =>
    chatRequest('/guardian-chat/settings', {
      method: 'PATCH',
      body: JSON.stringify(settings),
    }),

  sendTestSMS: (phoneNumber = null) =>
    chatRequest('/guardian-chat/send-test-sms', {
      method: 'POST',
      body: JSON.stringify({ phone_number: phoneNumber }),
    }),

  // WebSocket for real-time chat updates
  connectWebSocket: (conversationId) => {
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = (API_BASE.replace(/^https?:\/\//, '')).replace(/\/.*$/, '');
    const wsUrl = `${wsProtocol}//${host}/guardian-chat/ws/${conversationId}`;
    return new WebSocket(wsUrl);
  },
};
