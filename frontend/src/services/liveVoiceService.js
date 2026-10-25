import { getToken } from './api';

const API_BASE = (import.meta.env && import.meta.env.VITE_API_BASE_URL) || 'http://127.0.0.1:8000';

async function voiceRequest(endpoint, options = {}) {
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
    let msg = 'Live voice request failed.';
    if (typeof data.detail === 'string') msg = data.detail;
    else if (Array.isArray(data.detail)) msg = data.detail.map((d) => d.msg || JSON.stringify(d)).join(', ');
    const err = new Error(msg);
    err.status = response.status;
    throw err;
  }
  return data;
}

export const liveVoiceService = {
  // Session Lifecycle
  createSession: (roomCode) =>
    voiceRequest('/voice/session/create', {
      method: 'POST',
      body: JSON.stringify(roomCode ? { room_code: roomCode } : {}),
    }),

  joinSession: (sessionKey) =>
    voiceRequest('/voice/session/join', {
      method: 'POST',
      body: JSON.stringify({ room_code: sessionKey, session_id: sessionKey }),
    }),

  getSession: (sessionId) =>
    voiceRequest(`/voice/session/${sessionId}`, {
      method: 'GET',
    }),

  endSession: (sessionId) =>
    voiceRequest('/voice/session/end', {
      method: 'POST',
      body: JSON.stringify({ session_id: sessionId }),
    }),

  // WebRTC Signaling
  sendSignal: (sessionId, type, payload, targetId = null) =>
    voiceRequest(`/voice/session/signal/${sessionId}`, {
      method: 'POST',
      body: JSON.stringify({ type, payload, target_id: targetId }),
    }),

  getSignals: (sessionId) =>
    voiceRequest(`/voice/session/signals/${sessionId}`, {
      method: 'GET',
    }),

  // Audio Chunk Transcription
  transcribeAudio: async (audioBlob, language = null) => {
    const formData = new FormData();
    formData.append('audio_file', audioBlob, 'chunk.webm');
    if (language) formData.append('language', language);

    return voiceRequest('/voice/transcribe', {
      method: 'POST',
      body: formData,
    });
  },

  // Live Risk Analysis
  analyzeTranscript: ({ sessionId, text, speaker, language, syncGuardian = true }) =>
    voiceRequest('/voice/analyze', {
      method: 'POST',
      body: JSON.stringify({
        session_id: sessionId || null,
        text,
        speaker: speaker || 'Participant',
        language: language || null,
        sync_guardian: syncGuardian,
      }),
    }),

  // WebSocket Connection
  connectWebSocket: (sessionId) => {
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = (API_BASE.replace(/^https?:\/\//, '')).replace(/\/.*$/, '');
    const wsUrl = `${wsProtocol}//${host}/voice/ws/${sessionId}`;
    return new WebSocket(wsUrl);
  },
};
