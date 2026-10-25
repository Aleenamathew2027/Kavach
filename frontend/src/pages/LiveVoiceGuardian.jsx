import { useState, useEffect, useRef } from 'react';
import UserLayout from '../components/UserLayout';
import { liveVoiceService } from '../services/liveVoiceService';
import styles from './LiveVoiceGuardian.module.css';

const ICE_SERVERS = {
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
  ],
};

const DEMO_PRESETS = [
  {
    label: 'English OTP Scam',
    speaker: 'Participant 1',
    text: 'Your bank account has been blocked immediately. Please give me the OTP you received to verify.',
    lang: 'en',
  },
  {
    label: 'Malayalam Bank Scam',
    speaker: 'Participant 1',
    text: 'നിങ്ങളുടെ ബാങ്ക് അക്കൗണ്ട് ബ്ലോക്ക് ആയിട്ടുണ്ട്. OTP ഒന്ന് പറഞ്ഞുതരൂ.',
    lang: 'ml',
  },
  {
    label: 'Mixed Manglish Scam',
    speaker: 'Participant 1',
    text: 'Ningalude bank account block aayittundu. OTP paranju tharumo?',
    lang: 'mixed',
  },
  {
    label: 'Urgent Payment Demand',
    speaker: 'Participant 1',
    text: 'You must transfer the fine amount of 5000 rupees immediately via UPI or your account will be suspended.',
    lang: 'en',
  },
  {
    label: 'Normal Malayalam Chat',
    speaker: 'Participant 2',
    text: 'നമസ്കാരം, എന്തൊക്കെയുണ്ട് വിശേഷം? നാളെ കോളേജിൽ വരുന്നുണ്ടോ?',
    lang: 'ml',
  },
  {
    label: 'Normal English Chat',
    speaker: 'Participant 2',
    text: 'Good morning! Are we still meeting for the project discussion this afternoon?',
    lang: 'en',
  },
];

export default function LiveVoiceGuardian() {
  // Session State & Roles
  const [session, setSession] = useState(null);
  const [myRole, setMyRole] = useState('Participant 1'); // 'Participant 1' (host) or 'Participant 2' (peer)
  const [joinCode, setJoinCode] = useState('');
  const [callActive, setCallActive] = useState(false);
  const [callEnded, setCallEnded] = useState(false);
  const [callDuration, setCallDuration] = useState(0);
  const [peerConnected, setPeerConnected] = useState(false);
  const [isMuted, setIsMuted] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [loading, setLoading] = useState(false);
  const [copiedCode, setCopiedCode] = useState(false);

  // Language & Audio Setup
  const [languageMode, setLanguageMode] = useState('en'); // 'en', 'ml', 'mixed'
  const [sttStatus, setSttStatus] = useState('Standby');
  const [micPermission, setMicPermission] = useState('prompt'); // 'prompt', 'granted', 'denied'
  const [demoMode, setDemoMode] = useState(true);
  const [customDemoText, setCustomDemoText] = useState('');
  const [demoSpeaker, setDemoSpeaker] = useState('Participant 1');

  // Real-time Conversation & Risk Data
  const [transcripts, setTranscripts] = useState([]);
  const [riskAssessment, setRiskAssessment] = useState({
    risk_level: 'SAFE',
    risk_score: 0,
    detected_indicators: [],
    reasons: ['Listening for conversation. KAVACH Live Voice Guardian active.'],
    recommended_action: 'Speak normally. Real-time protection is active.',
    summary: 'Audio stream clear.',
    detected_language: 'en',
  });
  const [peakRisk, setPeakRisk] = useState({ level: 'SAFE', score: 0 });
  const [guardianAlertSent, setGuardianAlertSent] = useState(false);

  // WebRTC & Audio Refs
  const localStreamRef = useRef(null);
  const peerConnectionRef = useRef(null);
  const remoteAudioRef = useRef(null);
  const wsRef = useRef(null);
  const timerRef = useRef(null);
  const pollTimerRef = useRef(null);
  const recognitionRef = useRef(null);
  const iceCandidateQueueRef = useRef([]);
  const transcriptBottomRef = useRef(null);

  // Synchronized Refs to avoid stale closures in event listeners
  const myRoleRef = useRef(myRole);
  myRoleRef.current = myRole;
  const languageModeRef = useRef(languageMode);
  languageModeRef.current = languageMode;
  const callActiveRef = useRef(callActive);
  callActiveRef.current = callActive;
  const sessionRef = useRef(session);
  sessionRef.current = session;

  // Auto-scroll transcript stream
  useEffect(() => {
    transcriptBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [transcripts]);

  // Duration Timer
  useEffect(() => {
    if (callActive) {
      timerRef.current = setInterval(() => {
        setCallDuration((prev) => prev + 1);
      }, 1000);
    } else {
      if (timerRef.current) clearInterval(timerRef.current);
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [callActive]);

  // Periodic Session Sync Fallback
  useEffect(() => {
    if (!callActive || !session?.session_id) return;
    pollTimerRef.current = setInterval(async () => {
      try {
        const details = await liveVoiceService.getSession(session.session_id);
        if (details) {
          if (details.participant_count >= 2) {
            setPeerConnected(true);
          }
          if (details.peak_risk_score > peakRisk.score) {
            setPeakRisk({ level: details.peak_risk_level, score: details.peak_risk_score });
          }
        }
      } catch (_) {}
    }, 3500);

    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, [callActive, session?.session_id, peakRisk.score]);

  const formatDuration = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
  };

  const getLocaleForMode = (mode) => {
    if (mode === 'ml') return 'ml-IN';
    if (mode === 'mixed') return 'ml-IN';
    return 'en-IN';
  };

  // ── Language Selector Change Handler ──
  const handleLanguageChange = (newMode) => {
    setLanguageMode(newMode);
    languageModeRef.current = newMode;
    const targetLocale = getLocaleForMode(newMode);

    if (recognitionRef.current) {
      try {
        recognitionRef.current.lang = targetLocale;
        setSttStatus(`Listening (${targetLocale})`);
        // Restart speech recognition so the browser engine immediately loads the new locale
        recognitionRef.current.stop();
      } catch (e) {
        console.warn('Speech recognition language reconfiguration note:', e);
      }
    }

    // Broadcast language update to peer over WebSocket
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(
        JSON.stringify({
          type: 'language_change',
          payload: { language: newMode },
        })
      );
    }
  };

  // ── 1. Create Call Session (Participant 1) ──
  const handleCreateCall = async () => {
    setErrorMsg('');
    setLoading(true);
    try {
      const res = await liveVoiceService.createSession();
      setSession(res);
      setMyRole('Participant 1');
      myRoleRef.current = 'Participant 1';
      setPeerConnected(false);
      await startCallSession(res.session_id, true);
    } catch (err) {
      console.error('Failed to create call:', err);
      setErrorMsg(err.message || 'Unable to create call session. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // ── 2. Join Call Session (Participant 2) ──
  const handleJoinCall = async () => {
    if (!joinCode.trim()) {
      setErrorMsg('Please enter a valid Room Code or Session ID.');
      return;
    }
    setErrorMsg('');
    setLoading(true);
    try {
      const res = await liveVoiceService.joinSession(joinCode.trim().toUpperCase());
      setSession(res);
      setMyRole('Participant 2');
      myRoleRef.current = 'Participant 2';
      setPeerConnected(true);
      await startCallSession(res.session_id, false);
    } catch (err) {
      console.error('Failed to join call:', err);
      setErrorMsg(err.message || 'Unable to join call session. Verify room code.');
    } finally {
      setLoading(false);
    }
  };

  // ── WebRTC Signaling Helpers ──
  const createAndSendOffer = async () => {
    const pc = peerConnectionRef.current;
    if (!pc || pc.signalingState === 'closed') return;
    try {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ type: 'offer', payload: offer }));
      }
    } catch (err) {
      console.error('Error creating SDP offer:', err);
    }
  };

  const handleIncomingOffer = async (offerPayload) => {
    const pc = peerConnectionRef.current;
    if (!pc || pc.signalingState === 'closed') return;
    try {
      await pc.setRemoteDescription(new RTCSessionDescription(offerPayload));
      // Flush any queued ICE candidates that arrived before the offer
      while (iceCandidateQueueRef.current.length > 0) {
        const queuedCandidate = iceCandidateQueueRef.current.shift();
        try {
          await pc.addIceCandidate(new RTCIceCandidate(queuedCandidate));
        } catch (iceErr) {
          console.warn('ICE candidate addition error on offer receipt:', iceErr);
        }
      }

      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ type: 'answer', payload: answer }));
      }
      setPeerConnected(true);
    } catch (err) {
      console.error('Error handling incoming SDP offer:', err);
    }
  };

  const handleIncomingAnswer = async (answerPayload) => {
    const pc = peerConnectionRef.current;
    if (!pc || pc.signalingState === 'closed') return;
    try {
      await pc.setRemoteDescription(new RTCSessionDescription(answerPayload));
      // Flush any queued ICE candidates that arrived before the answer
      while (iceCandidateQueueRef.current.length > 0) {
        const queuedCandidate = iceCandidateQueueRef.current.shift();
        try {
          await pc.addIceCandidate(new RTCIceCandidate(queuedCandidate));
        } catch (iceErr) {
          console.warn('ICE candidate addition error on answer receipt:', iceErr);
        }
      }
      setPeerConnected(true);
    } catch (err) {
      console.error('Error handling incoming SDP answer:', err);
    }
  };

  const handleIncomingCandidate = async (candidatePayload) => {
    const pc = peerConnectionRef.current;
    if (!pc || pc.signalingState === 'closed') return;
    try {
      if (pc.remoteDescription && pc.remoteDescription.type) {
        await pc.addIceCandidate(new RTCIceCandidate(candidatePayload));
      } else {
        iceCandidateQueueRef.current.push(candidatePayload);
      }
    } catch (err) {
      console.warn('ICE candidate processing note:', err);
    }
  };

  // ── 3. Start Call Session (Media + WebRTC + WebSocket) ──
  const startCallSession = async (sessionId, isHost) => {
    setCallActive(true);
    callActiveRef.current = true;
    setCallEnded(false);
    setCallDuration(0);
    setTranscripts([]);
    setPeakRisk({ level: 'SAFE', score: 0 });
    setGuardianAlertSent(false);
    iceCandidateQueueRef.current = [];

    // Request Microphone Permission
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
      localStreamRef.current = stream;
      setMicPermission('granted');
    } catch (micErr) {
      console.warn('Microphone permission not granted or device unavailable:', micErr);
      setMicPermission('denied');
      setErrorMsg('Microphone access was denied or device not found. You can still test using the Demo Simulator below.');
    }

    // Initialize WebRTC PeerConnection
    try {
      const pc = new RTCPeerConnection(ICE_SERVERS);
      peerConnectionRef.current = pc;

      // Add local audio tracks to peer connection
      if (localStreamRef.current) {
        localStreamRef.current.getAudioTracks().forEach((track) => {
          pc.addTrack(track, localStreamRef.current);
        });
      }

      // Handle remote incoming audio stream
      pc.ontrack = (event) => {
        if (remoteAudioRef.current) {
          if (event.streams && event.streams[0]) {
            remoteAudioRef.current.srcObject = event.streams[0];
          } else {
            let inboundStream = remoteAudioRef.current.srcObject;
            if (!inboundStream) {
              inboundStream = new MediaStream();
              remoteAudioRef.current.srcObject = inboundStream;
            }
            inboundStream.addTrack(event.track);
          }
          remoteAudioRef.current.volume = 1.0;
          remoteAudioRef.current.muted = false;
          remoteAudioRef.current.play().catch((err) => {
            console.warn('Remote audio playback notice:', err);
          });
        }
      };

      // Send local ICE candidates to peer
      pc.onicecandidate = (event) => {
        if (event.candidate && wsRef.current?.readyState === WebSocket.OPEN) {
          wsRef.current.send(
            JSON.stringify({
              type: 'candidate',
              payload: event.candidate,
            })
          );
        }
      };

      pc.onconnectionstatechange = () => {
        if (pc.connectionState === 'connected') {
          setPeerConnected(true);
        } else if (pc.connectionState === 'disconnected' || pc.connectionState === 'failed') {
          setPeerConnected(false);
        }
      };
    } catch (pcErr) {
      console.error('RTCPeerConnection init error:', pcErr);
    }

    // Connect WebSocket for Real-time Signaling & Transcript Sync
    try {
      const ws = liveVoiceService.connectWebSocket(sessionId);
      wsRef.current = ws;

      ws.onopen = async () => {
        if (!isHost) {
          // Participant 2 announces presence to Participant 1
          ws.send(JSON.stringify({ type: 'peer_ready', speaker: 'Participant 2' }));
        }
      };

      ws.onmessage = async (event) => {
        try {
          const msg = JSON.parse(event.data);

          if (msg.type === 'peer_joined' || msg.type === 'peer_ready') {
            setPeerConnected(true);
            // Host sends offer when peer joins and is ready
            if (isHost) {
              await createAndSendOffer();
            }
          } else if (msg.type === 'peer_waiting') {
            setPeerConnected(true);
            if (isHost) {
              await createAndSendOffer();
            }
          } else if (msg.type === 'offer') {
            await handleIncomingOffer(msg.payload);
          } else if (msg.type === 'answer') {
            await handleIncomingAnswer(msg.payload);
          } else if (msg.type === 'candidate') {
            await handleIncomingCandidate(msg.payload);
          } else if (msg.type === 'transcript') {
            handleIncomingTranscript(msg.payload);
          } else if (msg.type === 'language_change') {
            if (msg.payload?.language) {
              setLanguageMode(msg.payload.language);
              languageModeRef.current = msg.payload.language;
            }
          } else if (msg.type === 'peer_disconnected') {
            setPeerConnected(false);
            setErrorMsg('The other participant disconnected from the voice session.');
          }
        } catch (wsMsgErr) {
          console.warn('WebSocket message handling error:', wsMsgErr);
        }
      };

      ws.onerror = (e) => console.warn('Voice WebSocket note:', e);
    } catch (wsErr) {
      console.warn('WebSocket connection fallback:', wsErr);
    }

    // Start Real-time Speech Recognition
    startSpeechRecognition(sessionId);
  };

  // ── 4. Real-time Speech-to-Text Recognition ──
  const startSpeechRecognition = (sessionId) => {
    const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (SpeechRec) {
      try {
        const recognition = new SpeechRec();
        recognitionRef.current = recognition;
        recognition.continuous = true;
        recognition.interimResults = false;

        const currentLocale = getLocaleForMode(languageModeRef.current);
        recognition.lang = currentLocale;

        recognition.onresult = (event) => {
          const lastIdx = event.results.length - 1;
          const transcriptText = event.results[lastIdx][0]?.transcript?.trim();
          if (transcriptText) {
            const currentSpeaker = myRoleRef.current;
            processUtterance(sessionId, currentSpeaker, transcriptText, languageModeRef.current);
          }
        };

        recognition.onerror = (e) => {
          console.warn('Speech recognition warning:', e.error);
        };

        recognition.onend = () => {
          // Restart if call is still active
          if (callActiveRef.current && recognitionRef.current) {
            try {
              recognitionRef.current.lang = getLocaleForMode(languageModeRef.current);
              recognitionRef.current.start();
            } catch (_) {}
          }
        };

        recognition.start();
        setSttStatus(`Active (${currentLocale})`);
      } catch (sttErr) {
        console.warn('Speech recognition start note:', sttErr);
        setSttStatus('Standby / Notice');
      }
    } else {
      setSttStatus('Web Speech API not supported in this browser (Chrome / Edge recommended)');
    }
  };

  // ── 5. Process and Analyze Utterance ──
  const processUtterance = async (sessionId, speaker, text, langHint) => {
    if (!text || !text.trim()) return;

    try {
      const activeSessionId = sessionId || sessionRef.current?.session_id;
      const speakerId = speaker || myRoleRef.current;

      const analysis = await liveVoiceService.analyzeTranscript({
        sessionId: activeSessionId,
        text: text.trim(),
        speaker: speakerId,
        language: langHint,
        syncGuardian: true,
      });

      const newTurn = {
        id: `${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        speaker: speakerId,
        text: text.trim(),
        language: analysis.detected_language || langHint || 'en',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        risk_score: analysis.risk_score,
        risk_level: analysis.risk_level,
      };

      setTranscripts((prev) => [...prev, newTurn]);
      setRiskAssessment(analysis);

      // Compounding peak risk
      setPeakRisk((prev) => {
        if (analysis.risk_score > prev.score) {
          return { level: analysis.risk_level, score: analysis.risk_score };
        }
        return prev;
      });

      if (analysis.guardian_alert_sent) {
        setGuardianAlertSent(true);
      }

      // Broadcast turn and analysis to peer over WebSocket
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(
          JSON.stringify({
            type: 'transcript',
            payload: {
              turn: newTurn,
              analysis,
            },
          })
        );
      }
    } catch (err) {
      console.error('Error analyzing live speech:', err);
    }
  };

  const handleIncomingTranscript = ({ turn, analysis }) => {
    if (turn) {
      // Append peer transcript - never overwrite existing turns
      setTranscripts((prev) => [...prev, turn]);
    }
    if (analysis) {
      // Update overall call risk assessment using speech from either participant
      setRiskAssessment(analysis);
      setPeakRisk((prev) => {
        if (analysis.risk_score > prev.score) {
          return { level: analysis.risk_level, score: analysis.risk_score };
        }
        return prev;
      });
      if (analysis.guardian_alert_sent) {
        setGuardianAlertSent(true);
      }
    }
  };

  // ── 6. Mute / Unmute Microphone ──
  const toggleMute = () => {
    if (localStreamRef.current) {
      const audioTrack = localStreamRef.current.getAudioTracks()[0];
      if (audioTrack) {
        audioTrack.enabled = !audioTrack.enabled;
        setIsMuted(!audioTrack.enabled);
      }
    } else {
      setIsMuted(!isMuted);
    }
  };

  // ── 7. End Call ──
  const handleEndCall = async () => {
    setCallActive(false);
    callActiveRef.current = false;
    setCallEnded(true);
    setPeerConnected(false);

    // Stop recognition
    if (recognitionRef.current) {
      try {
        recognitionRef.current.stop();
        recognitionRef.current = null;
      } catch (_) {}
    }

    // Stop local audio tracks
    if (localStreamRef.current) {
      localStreamRef.current.getTracks().forEach((track) => track.stop());
      localStreamRef.current = null;
    }

    // Close WebRTC
    if (peerConnectionRef.current) {
      peerConnectionRef.current.close();
      peerConnectionRef.current = null;
    }

    // Close WebSocket
    if (wsRef.current) {
      try {
        wsRef.current.close();
        wsRef.current = null;
      } catch (_) {}
    }

    if (pollTimerRef.current) {
      clearInterval(pollTimerRef.current);
    }

    // Notify backend
    if (session?.session_id) {
      try {
        await liveVoiceService.endSession(session.session_id);
      } catch (e) {
        console.warn('End session notification note:', e);
      }
    }
  };

  // ── 8. Demo Simulator Triggers ──
  const handleTriggerDemoPreset = (preset) => {
    processUtterance(session?.session_id, demoSpeaker, preset.text, preset.lang);
  };

  const handleTriggerCustomDemo = () => {
    if (!customDemoText.trim()) return;
    processUtterance(session?.session_id, demoSpeaker, customDemoText.trim(), languageMode);
    setCustomDemoText('');
  };

  const copyRoomCode = () => {
    const code = session?.room_code;
    if (code) {
      navigator.clipboard.writeText(code);
      setCopiedCode(true);
      setTimeout(() => setCopiedCode(false), 2000);
    }
  };

  // Helpers for badge and banner styles
  const getRiskBannerClass = (level) => {
    if (level === 'HIGH RISK') return styles.riskBannerHigh;
    if (level === 'SUSPICIOUS') return styles.riskBannerSuspicious;
    return styles.riskBannerSafe;
  };

  const getRiskColor = (level) => {
    if (level === 'HIGH RISK') return '#ef4444';
    if (level === 'SUSPICIOUS') return '#f59e0b';
    return '#10b981';
  };

  return (
    <UserLayout
      eyebrow="REAL-TIME THREAT SENTINEL"
      title="KAVACH LIVE VOICE GUARDIAN"
      subtitle="Real-Time Voice Scam & Vishing Detection for English, Malayalam, and Mixed Conversational Speech"
    >
      <div className={styles.container}>
        {/* Remote Audio Element for WebRTC audio playback */}
        <audio ref={remoteAudioRef} autoPlay playsInline controls={false} />

        {/* Global Error Banner */}
        {errorMsg && (
          <div
            style={{
              background: 'rgba(239, 68, 68, 0.15)',
              border: '1px solid rgba(239, 68, 68, 0.4)',
              color: '#fca5a5',
              padding: '12px 18px',
              borderRadius: '6px',
              fontSize: '13.5px',
              fontWeight: '600',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <span>⚠ {errorMsg}</span>
            <button
              onClick={() => setErrorMsg('')}
              style={{
                background: 'transparent',
                color: '#fca5a5',
                border: 'none',
                cursor: 'pointer',
                fontSize: '16px',
              }}
            >
              ✕
            </button>
          </div>
        )}

        {/* ── VIEW 1: PRE-CALL / LOBBY INTERFACE ── */}
        {!callActive && (
          <div className={styles.lobbyCard}>
            <div className={styles.lobbyHeader}>
              <div className={styles.lobbyTitleWrap}>
                <h2 className={styles.lobbyTitle}>
                  <span>🎙️</span> Two-Person Voice Call Protection
                </h2>
                <p className={styles.lobbySubtitle}>
                  Start an encrypted browser-to-browser voice call. KAVACH analyzes live speech chunks from both
                  participants in English, Malayalam script, and Manglish to deliver real-time scam advisories.
                </p>
              </div>
              <span className={styles.modeBadge}>WebRTC Audio • Real-Time STT</span>
            </div>

            {/* Session Actions Grid */}
            <div className={styles.lobbyGrid}>
              {/* Option A: Create Call (Participant 1) */}
              <div className={styles.actionBox}>
                <div>
                  <div className={styles.actionBoxTitle}>
                    <span>✦</span> Create New Voice Call (Participant 1)
                  </div>
                  <p className={styles.actionBoxDesc}>
                    Initialize a secured 2-person voice call room. Share the generated Room Code with Participant 2 to start the call.
                  </p>
                </div>
                <button
                  type="button"
                  className={styles.primaryBtn}
                  onClick={handleCreateCall}
                  disabled={loading}
                  id="create-call-button"
                >
                  {loading ? 'Initializing Session…' : 'Create Call Session →'}
                </button>
              </div>

              {/* Option B: Join Call (Participant 2) */}
              <div className={styles.actionBox}>
                <div>
                  <div className={styles.actionBoxTitle}>
                    <span>👥</span> Join Existing Call (Participant 2)
                  </div>
                  <p className={styles.actionBoxDesc}>
                    Enter the 6-character room code (e.g. KV-8492) generated by Participant 1 to join the active call.
                  </p>
                </div>
                <div className={styles.inputGroup}>
                  <input
                    type="text"
                    className={styles.inputField}
                    placeholder="e.g. KV-8492"
                    value={joinCode}
                    onChange={(e) => setJoinCode(e.target.value.toUpperCase())}
                    maxLength={10}
                    id="join-code-input"
                  />
                  <button
                    type="button"
                    className={styles.secondaryBtn}
                    onClick={handleJoinCall}
                    disabled={loading || !joinCode.trim()}
                    id="join-call-button"
                  >
                    Join Call
                  </button>
                </div>
              </div>
            </div>

            {/* Settings & Language Configuration Bar */}
            <div className={styles.settingsBar}>
              <div className={styles.settingsGroup}>
                <span style={{ color: 'var(--kavach-quicksand)', fontWeight: 600 }}>Language Mode:</span>
                <select
                  className={styles.selectInput}
                  value={languageMode}
                  onChange={(e) => handleLanguageChange(e.target.value)}
                  id="language-select-lobby"
                >
                  <option value="en">English (en-IN)</option>
                  <option value="ml">മലയാളം (Malayalam - ml-IN)</option>
                  <option value="mixed">Mixed / Manglish (മലയാളം + English)</option>
                </select>
              </div>

              <div className={styles.settingsGroup}>
                <span style={{ color: 'var(--kavach-shellstone)', fontSize: '13px' }}>
                  Microphone Status:
                  {micPermission === 'granted' ? (
                    <span style={{ color: '#34d399', marginLeft: '6px', fontWeight: 700 }}>● Active</span>
                  ) : micPermission === 'denied' ? (
                    <span style={{ color: '#ef4444', marginLeft: '6px', fontWeight: 700 }}>✕ Blocked</span>
                  ) : (
                    <span style={{ color: 'var(--kavach-quicksand)', marginLeft: '6px' }}>○ Standby</span>
                  )}
                </span>
              </div>
            </div>

            {/* Post-Call Summary Banner if ended */}
            {callEnded && (
              <div
                style={{
                  background: 'rgba(17, 34, 80, 0.7)',
                  border: '1px solid rgba(217, 203, 194, 0.2)',
                  borderRadius: '6px',
                  padding: '20px 24px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '16px',
                }}
              >
                <div>
                  <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--kavach-quicksand)' }}>
                    CALL SESSION COMPLETED
                  </span>
                  <div style={{ fontSize: '15px', fontWeight: 700, marginTop: '4px' }}>
                    Call Duration: {formatDuration(callDuration)} • Transcripts Analyzed: {transcripts.length}
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <span
                    style={{
                      background: peakRisk.level === 'HIGH RISK' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                      color: peakRisk.level === 'HIGH RISK' ? '#fca5a5' : '#6ee7b7',
                      border: `1px solid ${peakRisk.level === 'HIGH RISK' ? '#ef4444' : '#10b981'}`,
                      padding: '6px 14px',
                      borderRadius: '4px',
                      fontSize: '12px',
                      fontWeight: 700,
                    }}
                  >
                    Peak Threat: {peakRisk.level} ({peakRisk.score}/100)
                  </span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── VIEW 2: ACTIVE CALL INTERFACE ── */}
        {callActive && (
          <>
            {/* Call Control Bar with Live Language Switcher */}
            <div className={styles.callActiveBar}>
              <div className={styles.callStatusWrap}>
                {peerConnected ? (
                  <div className={styles.activeDotPill}>
                    <span className={styles.pulseDot} />
                    <span>CALL ACTIVE (2 PARTICIPANTS)</span>
                  </div>
                ) : (
                  <div className={styles.waitingBadge}>
                    <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#fbbf24' }} />
                    <span>WAITING FOR PARTICIPANT 2</span>
                  </div>
                )}
                <div className={styles.durationTimer}>⏱ {formatDuration(callDuration)}</div>
                {session?.room_code && (
                  <div
                    style={{
                      background: 'rgba(224, 197, 143, 0.1)',
                      border: '1px solid rgba(224, 197, 143, 0.3)',
                      borderRadius: '4px',
                      padding: '4px 10px',
                      fontSize: '12px',
                      fontFamily: 'monospace',
                      color: 'var(--kavach-quicksand)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                    }}
                  >
                    <span>Room: {session.room_code}</span>
                    <button
                      type="button"
                      onClick={copyRoomCode}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--kavach-swan-wing)',
                        cursor: 'pointer',
                        fontSize: '11px',
                        padding: 0,
                      }}
                    >
                      {copiedCode ? '✓ Copied' : '📋 Copy'}
                    </button>
                  </div>
                )}
              </div>

              {/* Language Selector during Active Call */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ fontSize: '12.5px', color: 'var(--kavach-quicksand)', fontWeight: 600 }}>Language:</span>
                <select
                  className={styles.selectInput}
                  value={languageMode}
                  onChange={(e) => handleLanguageChange(e.target.value)}
                  id="language-select-active"
                >
                  <option value="en">English</option>
                  <option value="ml">മലയാളം (Malayalam)</option>
                  <option value="mixed">Mixed / Manglish</option>
                </select>
              </div>

              <div className={styles.callControls}>
                <button
                  type="button"
                  className={`${styles.controlBtn} ${isMuted ? styles.controlBtnActive : ''}`}
                  onClick={toggleMute}
                  id="mute-button"
                >
                  <span>{isMuted ? '🔇' : '🎙️'}</span>
                  <span>{isMuted ? 'Unmute Mic' : 'Mute Mic'}</span>
                </button>
                <button
                  type="button"
                  className={styles.endCallBtn}
                  onClick={handleEndCall}
                  id="end-call-button"
                >
                  <span>📞</span>
                  <span>End Call</span>
                </button>
              </div>
            </div>

            {/* Waiting Notice if Participant 2 hasn't connected yet */}
            {!peerConnected && myRole === 'Participant 1' && (
              <div
                style={{
                  background: 'rgba(245, 158, 11, 0.1)',
                  border: '1px solid rgba(245, 158, 11, 0.3)',
                  color: '#fbbf24',
                  padding: '12px 18px',
                  borderRadius: '6px',
                  fontSize: '13px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '12px',
                }}
              >
                <span>
                  ⏳ <strong>Room Created:</strong> Waiting for Participant 2 to join. Share room code{' '}
                  <strong style={{ letterSpacing: '1px' }}>{session?.room_code}</strong>. Audio will begin automatically once connected.
                </span>
                <button
                  type="button"
                  onClick={copyRoomCode}
                  className={styles.secondaryBtn}
                  style={{ padding: '6px 12px', fontSize: '12px' }}
                >
                  {copiedCode ? '✓ Copied Room Code' : 'Copy Room Code'}
                </button>
              </div>
            )}

            {/* Main Call Grid: Transcripts & Real-Time Risk Analysis */}
            <div className={styles.callGrid}>
              {/* Left Column: Participants & Live Conversation-style Transcript */}
              <div className={styles.leftColumn}>
                {/* Participants Status Row */}
                <div className={styles.participantsRow}>
                  {/* Participant 1 Card */}
                  <div className={styles.participantCard}>
                    <div className={styles.participantAvatar}>P1</div>
                    <div className={styles.participantInfo}>
                      <span className={styles.participantName}>
                        Participant 1 {myRole === 'Participant 1' ? '(You)' : ''}
                      </span>
                      <span className={styles.participantStatus}>
                        <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#34d399' }} />
                        Connected {myRole === 'Participant 1' && isMuted ? '(Muted)' : ''}
                      </span>
                    </div>
                  </div>

                  {/* Participant 2 Card */}
                  <div className={styles.participantCard}>
                    <div
                      className={styles.participantAvatar}
                      style={{ borderColor: peerConnected ? 'rgba(56, 189, 248, 0.5)' : 'rgba(245, 158, 11, 0.4)' }}
                    >
                      P2
                    </div>
                    <div className={styles.participantInfo}>
                      <span className={styles.participantName}>
                        Participant 2 {myRole === 'Participant 2' ? '(You)' : ''}
                      </span>
                      {peerConnected ? (
                        <span className={styles.participantStatus}>
                          <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#34d399' }} />
                          Connected {myRole === 'Participant 2' && isMuted ? '(Muted)' : ''}
                        </span>
                      ) : (
                        <span style={{ fontSize: '12px', color: '#fbbf24', display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#fbbf24' }} />
                          Waiting to join...
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* STT Status & Language Info Line */}
                <div className={styles.sttInfoNotice}>
                  <span>🎙️</span>
                  <span>
                    <strong>Microphone STT:</strong> {sttStatus} • <strong>Language Mode:</strong>{' '}
                    {languageMode === 'ml' ? 'മലയാളം (Malayalam - ml-IN)' : languageMode === 'mixed' ? 'Mixed / Manglish' : 'English (en-IN)'}
                  </span>
                </div>

                {/* Live Transcript Stream (Conversation Style) */}
                <div className={styles.transcriptCard}>
                  <div className={styles.cardHeader}>
                    <h3 className={styles.cardTitle}>
                      <span>💬</span> TWO-WAY CONVERSATION TRANSCRIPT
                    </h3>
                    <span style={{ fontSize: '11px', color: 'var(--kavach-shellstone)', opacity: 0.8 }}>
                      {transcripts.length} turn(s) captured
                    </span>
                  </div>

                  <div className={styles.transcriptStream}>
                    {transcripts.length === 0 ? (
                      <div className={styles.emptyTranscript}>
                        <span style={{ fontSize: '32px' }}>🎙️</span>
                        <span>Microphones active. Waiting for spoken speech...</span>
                        <span style={{ fontSize: '12px', opacity: 0.75 }}>
                          Participant 1 &amp; Participant 2 speech will appear in chronological sequence.
                        </span>
                      </div>
                    ) : (
                      transcripts.map((t) => {
                        const isP1 = t.speaker === 'Participant 1';
                        return (
                          <div
                            key={t.id}
                            className={`${styles.transcriptBubble} ${isP1 ? styles.bubbleP1 : styles.bubbleP2}`}
                          >
                            <div className={styles.bubbleHeader}>
                              <span className={styles.bubbleSpeaker}>
                                {t.speaker} {myRole === t.speaker ? '(You)' : ''}
                              </span>
                              <div className={styles.bubbleMeta}>
                                <span className={styles.langPill}>
                                  {t.language === 'ml' ? 'MALAYALAM' : t.language === 'mixed' ? 'MIXED / MANGLISH' : 'ENGLISH'}
                                </span>
                                {t.risk_score >= 60 ? (
                                  <span className={styles.bubbleRiskHigh}>🔴 HIGH RISK ({t.risk_score})</span>
                                ) : t.risk_score >= 30 ? (
                                  <span className={styles.bubbleRiskSuspicious}>🟡 SUSPICIOUS ({t.risk_score})</span>
                                ) : (
                                  <span className={styles.bubbleRiskSafe}>🟢 SAFE</span>
                                )}
                                <span className={styles.bubbleTime}>{t.timestamp}</span>
                              </div>
                            </div>
                            <p className={styles.bubbleText}>"{t.text}"</p>
                          </div>
                        );
                      })
                    )}
                    <div ref={transcriptBottomRef} />
                  </div>
                </div>

                {/* Interactive Demo Presentation Simulator */}
                {demoMode && (
                  <div className={styles.demoPanel}>
                    <div className={styles.demoPanelHeader}>
                      <span className={styles.demoTitle}>⚡ FYP DEMO SIMULATOR • SIMULATE EITHER SPEAKER</span>
                      <select
                        style={{
                          background: 'rgba(10, 20, 50, 0.8)',
                          color: 'var(--kavach-swan-wing)',
                          border: '1px solid rgba(217, 203, 194, 0.2)',
                          borderRadius: '4px',
                          padding: '4px 8px',
                          fontSize: '11px',
                        }}
                        value={demoSpeaker}
                        onChange={(e) => setDemoSpeaker(e.target.value)}
                        id="demo-speaker-select"
                      >
                        <option value="Participant 1">Speaker: Participant 1</option>
                        <option value="Participant 2">Speaker: Participant 2</option>
                      </select>
                    </div>

                    <div className={styles.demoButtonGroup}>
                      {DEMO_PRESETS.map((p) => (
                        <button
                          key={p.label}
                          type="button"
                          className={styles.demoBtn}
                          onClick={() => handleTriggerDemoPreset({ ...p, speaker: demoSpeaker })}
                        >
                          {p.label} ({demoSpeaker})
                        </button>
                      ))}
                    </div>

                    <div className={styles.demoInputRow}>
                      <input
                        type="text"
                        className={styles.inputField}
                        placeholder={`Enter spoken phrase to test as ${demoSpeaker}...`}
                        value={customDemoText}
                        onChange={(e) => setCustomDemoText(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && handleTriggerCustomDemo()}
                        id="demo-custom-input"
                      />
                      <button
                        type="button"
                        className={styles.secondaryBtn}
                        onClick={handleTriggerCustomDemo}
                        disabled={!customDemoText.trim()}
                        id="demo-send-button"
                      >
                        Send Turn →
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Right Column: KAVACH Live Analysis (Receives & Combines Speech from Both Participants) */}
              <div className={styles.analysisCard}>
                <div className={styles.cardHeader}>
                  <h3 className={styles.cardTitle}>
                    <span>🛡️</span> KAVACH LIVE RISK ANALYSIS
                  </h3>
                  <span
                    style={{
                      fontSize: '10px',
                      fontWeight: 700,
                      letterSpacing: '1px',
                      color: 'var(--kavach-quicksand)',
                    }}
                  >
                    TWO-WAY VISHING SENTRY
                  </span>
                </div>

                {/* Dynamic Risk Level Banner */}
                <div className={getRiskBannerClass(riskAssessment.risk_level)}>
                  <div className={styles.riskBannerLeft}>
                    <span className={styles.riskBannerLabel}>CALL RISK LEVEL</span>
                    <span
                      className={styles.riskBannerLevel}
                      style={{ color: getRiskColor(riskAssessment.risk_level) }}
                    >
                      {riskAssessment.risk_level === 'HIGH RISK' && '🔴 HIGH RISK'}
                      {riskAssessment.risk_level === 'SUSPICIOUS' && '🟡 SUSPICIOUS'}
                      {riskAssessment.risk_level === 'SAFE' && '🟢 SAFE'}
                    </span>
                  </div>

                  <div className={styles.riskScoreCircle}>
                    <span
                      className={styles.riskScoreNum}
                      style={{ color: getRiskColor(riskAssessment.risk_level) }}
                    >
                      {riskAssessment.risk_score}
                    </span>
                    <span className={styles.riskScoreTotal}>/ 100</span>
                  </div>
                </div>

                {/* Detected Indicators */}
                <div className={styles.riskSection}>
                  <span className={styles.sectionHeading}>DETECTED SCAM PATTERNS</span>
                  {riskAssessment.detected_indicators?.length > 0 ? (
                    <ul className={styles.indicatorsList}>
                      {riskAssessment.detected_indicators.map((ind, i) => (
                        <li key={i} className={styles.indicatorItem}>
                          <span
                            className={styles.indicatorDot}
                            style={{
                              background: riskAssessment.risk_level === 'HIGH RISK' ? '#ef4444' : '#f59e0b',
                            }}
                          />
                          <span>{ind}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <span style={{ fontSize: '13px', color: 'var(--kavach-shellstone)', opacity: 0.7 }}>
                      • Zero suspicious patterns flagged.
                    </span>
                  )}
                </div>

                {/* Explanation */}
                <div className={styles.riskSection}>
                  <span className={styles.sectionHeading}>ANALYSIS EXPLANATION</span>
                  <div className={styles.explanationText}>
                    {riskAssessment.reasons?.map((reason, i) => (
                      <p key={i} style={{ marginBottom: '6px' }}>
                        {reason}
                      </p>
                    ))}
                  </div>
                </div>

                {/* Actionable Recommendation */}
                <div className={styles.riskSection}>
                  <span className={styles.sectionHeading}>RECOMMENDED ACTION</span>
                  <div className={styles.recommendationBox}>
                    {riskAssessment.recommended_action}
                  </div>
                </div>

                {/* Guardian Sync Status if High Risk */}
                {guardianAlertSent && (
                  <div className={styles.guardianSyncNotice}>
                    <span>👥</span>
                    <span>
                      Guardian Alert Synced: A sanitized threat alert has been dispatched to your trusted Guardian
                      without sharing your private conversational details.
                    </span>
                  </div>
                )}

                {/* Advisory Notice */}
                <p className={styles.advisoryNote}>
                  🛡️ Advisory Notice: KAVACH Live Voice Guardian provides advisory risk warnings on live speech
                  from both Participant 1 and Participant 2. Maintain vigilance when sharing sensitive details.
                </p>
              </div>
            </div>
          </>
        )}
      </div>
    </UserLayout>
  );
}
