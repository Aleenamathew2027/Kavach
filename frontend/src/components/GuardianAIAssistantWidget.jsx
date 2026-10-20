import { useState, useRef, useEffect } from 'react';
import { api } from '../services/api';
import styles from './GuardianAIAssistantWidget.module.css';

const SAMPLE_PROMPTS = [
  'What threats were detected recently?',
  'What does this risk score mean?',
  'What should I do about a HIGH severity alert?',
  'How does KAVACH protect my family member?',
  'What is a phishing attack?',
  'How can I verify a suspicious link?',
];

/**
 * GuardianAIAssistantWidget — 3-state floating AI chatbox for guardian pages.
 * State 1: Collapsed floating pill (bottom-right)
 * State 2: Right-side chat panel (~420px)
 * State 3: Full-screen overlay
 */
export default function GuardianAIAssistantWidget() {
  // 'collapsed' | 'panel' | 'fullscreen'
  const [mode, setMode] = useState('collapsed');
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content:
        'Hello Guardian 🛡️ I am your KAVACH AI Security Assistant. I can help you understand security alerts, threat indicators, and how to protect your family member. What would you like to know?',
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    if (mode !== 'collapsed') {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, mode]);

  useEffect(() => {
    if (mode === 'panel' || mode === 'fullscreen') {
      setTimeout(() => inputRef.current?.focus(), 150);
    }
  }, [mode]);

  const sendMessage = async (text) => {
    const userText = (text || input).trim();
    if (!userText || loading) return;

    setInput('');
    setMessages((prev) => [...prev, { role: 'user', content: userText }]);
    setLoading(true);

    try {
      // Prepend guardian context to the message
      const contextualMessage = `[Guardian Context] ${userText}`;
      const res = await api.chatWithAI(contextualMessage, messages);
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: res.response || res.message || 'I could not generate a response. Please try again.' },
      ]);
    } catch (err) {
      console.error('Guardian AI chat error:', err);
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: 'I am currently unable to connect to the AI service. Please check your connection and try again.',
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const clearChat = () => {
    setMessages([
      {
        role: 'assistant',
        content:
          'Chat cleared. How can I assist you with your Guardian protection duties today?',
      },
    ]);
  };

  // ── STATE 1: COLLAPSED TRIGGER PILL ──────────────────────────
  if (mode === 'collapsed') {
    return (
      <button
        className={styles.floatingTrigger}
        onClick={() => setMode('panel')}
        aria-label="Open Guardian AI Assistant"
      >
        <span className={styles.triggerIcon}>🛡️</span>
        <span>Guardian AI</span>
      </button>
    );
  }

  // ── SHARED CHAT CONTENT ───────────────────────────────────────
  const chatContent = (
    <>
      {/* Header */}
      <div className={styles.panelHeader}>
        <div className={styles.headerLeft}>
          <span className={styles.headerIcon}>🛡️</span>
          <div>
            <div className={styles.headerTitle}>KAVACH Guardian AI</div>
            <div className={styles.headerSub}>Security Intelligence Assistant</div>
          </div>
        </div>
        <div className={styles.headerActions}>
          {mode === 'panel' ? (
            <button
              className={styles.headerBtn}
              onClick={() => setMode('fullscreen')}
              title="Expand to fullscreen"
            >
              ⤢
            </button>
          ) : (
            <button
              className={styles.headerBtn}
              onClick={() => setMode('panel')}
              title="Collapse to panel"
            >
              ⤡
            </button>
          )}
          <button
            className={styles.headerBtn}
            onClick={() => setMode('collapsed')}
            title="Minimize"
          >
            ✕
          </button>
        </div>
      </div>

      {/* Sample Prompts (only when few messages) */}
      {messages.length <= 1 && (
        <div className={styles.promptChips}>
          {SAMPLE_PROMPTS.slice(0, mode === 'fullscreen' ? 6 : 3).map((p, i) => (
            <button
              key={i}
              className={styles.promptChip}
              onClick={() => sendMessage(p)}
            >
              {p}
            </button>
          ))}
        </div>
      )}

      {/* Messages */}
      <div className={styles.messagesArea}>
        {messages.map((msg, i) => (
          <div
            key={i}
            className={`${styles.messageBubble} ${
              msg.role === 'user' ? styles.userBubble : styles.aiBubble
            }`}
          >
            {msg.role === 'assistant' && (
              <span className={styles.aiAvatar}>🛡️</span>
            )}
            <div className={styles.bubbleText}>{msg.content}</div>
          </div>
        ))}

        {loading && (
          <div className={`${styles.messageBubble} ${styles.aiBubble}`}>
            <span className={styles.aiAvatar}>🛡️</span>
            <div className={styles.typingDots}>
              <span />
              <span />
              <span />
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Footer */}
      <div className={styles.panelFooter}>
        <div className={styles.inputRow}>
          <textarea
            ref={inputRef}
            className={styles.chatInput}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask about threats, alerts, or how to protect your user…"
            rows={1}
            disabled={loading}
          />
          <button
            className={styles.sendBtn}
            onClick={() => sendMessage()}
            disabled={loading || !input.trim()}
            aria-label="Send message"
          >
            ➤
          </button>
        </div>
        <div className={styles.footerMeta}>
          <button className={styles.clearBtn} onClick={clearChat}>
            Clear chat
          </button>
          <span className={styles.privacyNote}>🔒 Guardian-encrypted session</span>
        </div>
      </div>
    </>
  );

  // ── STATE 2: RIGHT-SIDE PANEL ─────────────────────────────────
  if (mode === 'panel') {
    return (
      <div className={styles.chatPanel}>
        {chatContent}
      </div>
    );
  }

  // ── STATE 3: FULLSCREEN OVERLAY ───────────────────────────────
  return (
    <div className={styles.fullscreenOverlay}>
      <div className={styles.fullscreenContainer}>
        {chatContent}
      </div>
    </div>
  );
}
