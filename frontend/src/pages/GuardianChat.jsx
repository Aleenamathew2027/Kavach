import { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import GuardianLayout from '../components/GuardianLayout';
import VoiceMessagePlayer from '../components/VoiceMessagePlayer';
import { guardianChatService } from '../services/guardianChatService';
import styles from './GuardianChat.module.css';

export default function GuardianChat() {
  const [conversation, setConversation] = useState(null);
  const [messages, setMessages] = useState([]);
  const [inputText, setInputText] = useState('');
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  // Voice recording state
  const [isRecording, setIsRecording] = useState(false);
  const [recordingSeconds, setRecordingSeconds] = useState(0);
  const mediaRecorderRef = useRef(null);
  const audioChunksRef = useRef([]);
  const recordingTimerRef = useRef(null);

  // References
  const messagesEndRef = useRef(null);
  const wsRef = useRef(null);
  const pollTimerRef = useRef(null);

  const scrollToBottom = (behavior = 'smooth') => {
    messagesEndRef.current?.scrollIntoView({ behavior });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  useEffect(() => {
    let isMounted = true;

    async function initChat() {
      setLoading(true);
      setErrorMsg('');
      try {
        const conv = await guardianChatService.getConversation();
        if (!isMounted) return;
        setConversation(conv);

        const msgList = await guardianChatService.getMessages(conv.id);
        if (!isMounted) return;
        setMessages(msgList);

        // Connect WebSocket
        try {
          const ws = guardianChatService.connectWebSocket(conv.id);
          wsRef.current = ws;

          ws.onmessage = (event) => {
            try {
              const data = JSON.parse(event.data);
              if (data.type === 'new_message' && data.message) {
                setMessages((prev) => {
                  if (prev.some((m) => m.id === data.message.id)) return prev;
                  return [...prev, data.message];
                });
              }
            } catch (_) {}
          };
        } catch (wsErr) {
          console.warn('WebSocket fallback to polling:', wsErr);
        }
      } catch (err) {
        if (!isMounted) return;
        console.error('Error loading Guardian chat:', err);
        setErrorMsg(err.message || 'Unable to connect to Protected User chat.');
      } finally {
        if (isMounted) setLoading(false);
      }
    }

    initChat();

    // Background polling every 3.5s
    pollTimerRef.current = setInterval(async () => {
      try {
        const conv = await guardianChatService.getConversation();
        if (!isMounted) return;
        setConversation(conv);
        if (conv?.id) {
          const freshMessages = await guardianChatService.getMessages(conv.id);
          if (!isMounted) return;
          setMessages(freshMessages);
        }
      } catch (_) {}
    }, 3500);

    return () => {
      isMounted = false;
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
      if (wsRef.current) {
        try {
          wsRef.current.close();
        } catch (_) {}
      }
    };
  }, []);

  // Send Text Message
  const handleSendText = async (e) => {
    e?.preventDefault();
    const text = inputText.trim();
    if (!text || !conversation?.id || sending) return;

    setSending(true);
    setInputText('');
    try {
      const newMsg = await guardianChatService.sendTextMessage(conversation.id, text);
      setMessages((prev) => {
        if (prev.some((m) => m.id === newMsg.id)) return prev;
        return [...prev, newMsg];
      });
    } catch (err) {
      console.error('Error sending message:', err);
      setErrorMsg(err.message || 'Failed to send message.');
    } finally {
      setSending(false);
    }
  };

  // Voice Recording
  const startRecording = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      audioChunksRef.current = [];

      let mimeType = 'audio/webm';
      if (!MediaRecorder.isTypeSupported('audio/webm')) {
        if (MediaRecorder.isTypeSupported('audio/mp4')) mimeType = 'audio/mp4';
        else if (MediaRecorder.isTypeSupported('audio/ogg')) mimeType = 'audio/ogg';
      }

      const recorder = new MediaRecorder(stream, { mimeType });
      mediaRecorderRef.current = recorder;

      recorder.ondataavailable = (event) => {
        if (event.data && event.data.size > 0) {
          audioChunksRef.current.push(event.data);
        }
      };

      recorder.onstop = () => {
        stream.getTracks().forEach((track) => track.stop());
      };

      recorder.start(100);
      setIsRecording(true);
      setRecordingSeconds(0);

      recordingTimerRef.current = setInterval(() => {
        setRecordingSeconds((prev) => prev + 1);
      }, 1000);
    } catch (err) {
      console.error('Microphone access denied:', err);
      setErrorMsg('Microphone access was denied. Please allow mic permissions to record voice notes.');
    }
  };

  const cancelRecording = () => {
    if (recordingTimerRef.current) clearInterval(recordingTimerRef.current);
    if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
      mediaRecorderRef.current.stop();
    }
    audioChunksRef.current = [];
    setIsRecording(false);
    setRecordingSeconds(0);
  };

  const stopAndSendRecording = () => {
    if (recordingTimerRef.current) clearInterval(recordingTimerRef.current);
    if (!mediaRecorderRef.current) return;

    const recordedDuration = recordingSeconds;
    setIsRecording(false);
    setRecordingSeconds(0);
    setSending(true);

    mediaRecorderRef.current.onstop = async () => {
      try {
        const audioBlob = new Blob(audioChunksRef.current, {
          type: mediaRecorderRef.current.mimeType || 'audio/webm',
        });

        if (audioBlob.size > 0 && conversation?.id) {
          const newMsg = await guardianChatService.sendVoiceMessage(
            conversation.id,
            audioBlob,
            recordedDuration
          );
          setMessages((prev) => {
            if (prev.some((m) => m.id === newMsg.id)) return prev;
            return [...prev, newMsg];
          });
        }
      } catch (err) {
        console.error('Failed to send voice note:', err);
        setErrorMsg('Failed to upload voice message.');
      } finally {
        setSending(false);
      }
    };

    mediaRecorderRef.current.stop();
  };

  const formatTimer = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${String(secs).padStart(2, '0')}`;
  };

  const formatTimestamp = (isoString) => {
    if (!isoString) return '';
    try {
      return new Date(isoString).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (_) {
      return '';
    }
  };

  const guardedUser = conversation?.guarded_user || { full_name: 'Guarded User', email: '' };
  const userName = guardedUser.full_name || 'Aleena';
  const guardianName = 'Guardian';

  return (
    <GuardianLayout>
      <div className={styles.page}>
        <main className={styles.main}>
          <div className={styles.header}>
            <span className={styles.sectionPill}>SECURE MESSAGING CHANNEL</span>
            <h1 className={styles.title}>🔒 Private User Chat</h1>
            <p className={styles.subtitle}>
              Private communication between the linked User and Guardian
            </p>
          </div>

          {errorMsg && (
            <div className={styles.errorBanner}>
              <span>⚠ {errorMsg}</span>
              <button type="button" onClick={() => setErrorMsg('')} className={styles.closeErrorBtn}>
                ✕
              </button>
            </div>
          )}

          {/* Main Chat Box */}
          <div className={styles.chatCard}>
            {/* Header */}
            <div className={styles.chatHeader}>
              <div className={styles.headerInfo}>
                <div className={styles.avatar}>🛡️</div>
                <div>
                  <div className={styles.userRow}>
                    <h2 className={styles.userName}>{guardedUser.full_name}</h2>
                    <span className={styles.activePill}>
                      <span className={styles.dot} /> Guarded User
                    </span>
                  </div>
                  <span className={styles.userEmail}>{guardedUser.email} • Privacy-Preserving Channel</span>
                </div>
              </div>

              <div className={styles.headerActions}>
                <Link to="/guardian/alerts" className={styles.actionBtn}>
                  Security Alerts
                </Link>
                <Link to="/guardian/reports" className={styles.actionBtn}>
                  Incident Reports
                </Link>
              </div>
            </div>

            {/* Messages Feed */}
            <div className={styles.messagesContainer}>
              {loading ? (
                <div className={styles.emptyState}>
                  <span style={{ fontSize: '28px' }}>⌛</span>
                  <p>Connecting to secure chat channel…</p>
                </div>
              ) : messages.length === 0 ? (
                <div className={styles.emptyState}>
                  <span style={{ fontSize: '36px' }}>💬</span>
                  <h3>Direct Guardian Channel Active</h3>
                  <p>
                    No messages yet. Send a message or voice note to check in with your guarded user.
                    Real-time security sentry alerts will also arrive here.
                  </p>
                </div>
              ) : (
                messages.map((m) => {
                  const isSystem = m.sender_role === 'system' || m.message_type === 'SYSTEM_ALERT';
                  const isOwn = !isSystem && (m.sender_role === 'guardian');
                  const senderDisplayName = m.sender_role === 'user' ? userName : guardianName;

                  if (isSystem) {
                    return (
                      <div key={m.id} className={styles.systemAlertBubble}>
                        <div className={styles.systemAlertDivider}>
                          ──────── KAVACH SECURITY ALERT ────────
                        </div>
                        <div className={styles.systemAlertHeader}>
                          <span className={styles.systemShieldIcon}>🚨</span>
                          <div className={styles.systemAlertTitle}>
                            <strong>{m.alert_title || 'KAVACH THREAT SENTINEL ALERT'}</strong>
                            <span className={styles.severityBadge}>
                              {m.alert_severity || 'HIGH RISK'}
                            </span>
                          </div>
                          <span className={styles.messageTime}>{formatTimestamp(m.created_at)}</span>
                        </div>

                        <p className={styles.systemAlertContent}>
                          {m.text_content || 'A high-risk security scam was detected on the guarded user account.'}
                        </p>

                        <div className={styles.systemAlertActions}>
                          <Link to="/guardian/alerts" className={styles.alertViewBtn}>
                            Inspect Security Alert →
                          </Link>
                          {m.incident_report_id && (
                            <Link to={`/guardian/reports`} className={styles.reportViewBtn}>
                              Incident Report ({m.incident_report_id})
                            </Link>
                          )}
                        </div>
                      </div>
                    );
                  }

                  return (
                    <div
                      key={m.id}
                      className={`${styles.messageRow} ${isOwn ? styles.rowOwn : styles.rowPeer}`}
                    >
                      <div className={`${styles.bubble} ${isOwn ? styles.bubbleOwn : styles.bubblePeer}`}>
                        <div className={styles.bubbleHeader}>
                          <span className={styles.senderLabel}>
                            {senderDisplayName}
                          </span>
                          <span className={styles.bubbleTime}>{formatTimestamp(m.created_at)}</span>
                        </div>

                        {m.message_type === 'VOICE' ? (
                          <div className={styles.voiceWrapper}>
                            <VoiceMessagePlayer
                              messageId={m.id}
                              duration={m.voice_duration || 0}
                              isOwn={isOwn}
                            />
                          </div>
                        ) : (
                          <p className={styles.bubbleText}>{m.text_content}</p>
                        )}

                        {isOwn && (
                          <div className={styles.readIndicator}>
                            {m.is_read ? <span title="Read">✓✓</span> : <span title="Sent">✓</span>}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Input & Voice Controls */}
            <div className={styles.inputBar}>
              {isRecording ? (
                <div className={styles.recordingControls}>
                  <div className={styles.recordingPulse}>
                    <span className={styles.redDot} />
                    <span>Recording Guardian Voice Note: {formatTimer(recordingSeconds)}</span>
                  </div>

                  <div className={styles.recordingActions}>
                    <button
                      type="button"
                      onClick={cancelRecording}
                      className={styles.cancelRecordBtn}
                      title="Cancel recording"
                    >
                      ✕ Cancel
                    </button>
                    <button
                      type="button"
                      onClick={stopAndSendRecording}
                      className={styles.sendRecordBtn}
                      disabled={sending}
                    >
                      {sending ? 'Sending…' : '✓ Send Voice Note'}
                    </button>
                  </div>
                </div>
              ) : (
                <form onSubmit={handleSendText} className={styles.inputForm}>
                  <input
                    type="text"
                    className={styles.textInput}
                    placeholder={`Message ${guardedUser.full_name}…`}
                    value={inputText}
                    onChange={(e) => setInputText(e.target.value)}
                    disabled={sending}
                  />

                  <button
                    type="button"
                    onClick={startRecording}
                    className={styles.micBtn}
                    disabled={sending}
                    title="Record voice message"
                    aria-label="Record voice message"
                  >
                    🎙️
                  </button>

                  <button
                    type="submit"
                    className={styles.sendBtn}
                    disabled={!inputText.trim() || sending}
                    title="Send message"
                    aria-label="Send message"
                  >
                    {sending ? '…' : '➤'}
                  </button>
                </form>
              )}
            </div>
          </div>
        </main>
      </div>
    </GuardianLayout>
  );
}
