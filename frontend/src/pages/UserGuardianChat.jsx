import { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import UserLayout from '../components/UserLayout';
import VoiceMessagePlayer from '../components/VoiceMessagePlayer';
import { guardianChatService } from '../services/guardianChatService';
import styles from './UserGuardianChat.module.css';

export default function UserGuardianChat() {
  const [currentUser, setCurrentUser] = useState(null);
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

  // Auto-scroll to bottom of chat
  const scrollToBottom = (behavior = 'smooth') => {
    messagesEndRef.current?.scrollIntoView({ behavior });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Initial load
  useEffect(() => {
    let isMounted = true;

    async function initChat() {
      setLoading(true);
      setErrorMsg('');
      try {
        const [me, conv] = await Promise.all([
          api.getMe().catch(() => null),
          guardianChatService.getConversation(),
        ]);
        if (!isMounted) return;
        if (me) setCurrentUser(me);
        setConversation(conv);

        const msgList = await guardianChatService.getMessages(conv.id);
        if (!isMounted) return;
        setMessages(msgList);

        // Connect WebSocket for real-time updates
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
        setErrorMsg(err.message || 'Unable to connect to Guardian chat.');
      } finally {
        if (isMounted) setLoading(false);
      }
    }

    initChat();

    // Background polling fallback every 3.5 seconds
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

  // ── Send Text Message ──
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
      setErrorMsg(err.message || 'Failed to send text message.');
    } finally {
      setSending(false);
    }
  };

  // ── Voice Recording Controls ──
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
      console.error('Microphone access denied or error:', err);
      setErrorMsg('Microphone access was denied. Please allow mic permissions to record voice messages.');
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
        console.error('Failed to send voice message:', err);
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

  const isLinked = conversation?.is_guardian_linked;
  const userName = currentUser?.full_name || conversation?.guarded_user?.full_name || 'Aleena';
  const guardianName = 'Guardian';

  return (
    <UserLayout
      eyebrow="GUARDIAN PROTECTION CHANNEL"
      title="🔒 Private Guardian Chat"
      subtitle="Private communication between the linked User and Guardian"
    >
      <div className={styles.container}>
        {/* Error Alert */}
        {errorMsg && (
          <div className={styles.errorBanner}>
            <span>⚠ {errorMsg}</span>
            <button type="button" onClick={() => setErrorMsg('')} className={styles.closeErrorBtn}>
              ✕
            </button>
          </div>
        )}

        {/* Link / Status Notice if Guardian is not active */}
        {!loading && !isLinked && (
          <div className={styles.unlinkedBanner}>
            <div className={styles.unlinkedLeft}>
              <span className={styles.warningIcon}>⏳</span>
              <div>
                <strong>Guardian Not Currently Linked:</strong>
                <p>
                  Generate a 6-digit access code to connect your trusted guardian. Once paired, you can exchange
                  private voice messages and they will receive urgent threat alerts.
                </p>
              </div>
            </div>
            <Link to="/user/guardian" className={styles.pairBtn}>
              Generate Pairing Code →
            </Link>
          </div>
        )}

        {/* Main Chat Frame */}
        <div className={styles.chatCard}>
          {/* Header */}
          <div className={styles.chatHeader}>
            <div className={styles.headerInfo}>
              <div className={styles.avatar}>🛡️</div>
              <div>
                <div className={styles.guardianTitleRow}>
                  <h2 className={styles.guardianName}>Trusted Guardian Channel</h2>
                  {isLinked ? (
                    <span className={styles.statusPillActive}>
                      <span className={styles.activeDot} /> Linked &amp; Protected
                    </span>
                  ) : (
                    <span className={styles.statusPillInactive}>○ Pairing Code Standby</span>
                  )}
                </div>
                <span className={styles.headerSubtitle}>
                  Zero-Knowledge Storage • End-to-End Private Channel
                </span>
              </div>
            </div>

            <div className={styles.headerActions}>
              <Link to="/user/guardian" className={styles.secondaryHeaderBtn}>
                Pairing Access
              </Link>
            </div>
          </div>

          {/* Messages Feed */}
          <div className={styles.messagesContainer}>
            {loading ? (
              <div className={styles.emptyState}>
                <span style={{ fontSize: '28px' }}>⌛</span>
                <p>Loading secure conversation history…</p>
              </div>
            ) : messages.length === 0 ? (
              <div className={styles.emptyState}>
                <span style={{ fontSize: '36px' }}>💬</span>
                <h3>Secure Guardian Conversation</h3>
                <p>
                  No messages yet. Send a private text or voice note to your trusted guardian.
                  System alerts for high-risk threats will also appear here in real time.
                </p>
              </div>
            ) : (
              messages.map((m) => {
                const isSystem = m.sender_role === 'system' || m.message_type === 'SYSTEM_ALERT';
                const isOwn = !isSystem && (
                  (currentUser?.id && m.sender_id === currentUser.id && m.sender_role !== 'guardian') ||
                  m.sender_role === 'user'
                );
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
                        {m.text_content || 'High-risk security scam detected by KAVACH Sentinels.'}
                      </p>

                      <div className={styles.systemAlertActions}>
                        <Link to="/user/alerts" className={styles.alertViewBtn}>
                          View Security Alert Details →
                        </Link>
                        {m.incident_report_id && (
                          <Link to="/user/reports" className={styles.reportViewBtn}>
                            View Incident Report
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
                  <span>Recording Voice Note: {formatTimer(recordingSeconds)}</span>
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
                  placeholder="Type a message to your Guardian…"
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
      </div>
    </UserLayout>
  );
}
