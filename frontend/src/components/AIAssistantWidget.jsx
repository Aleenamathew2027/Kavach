import { useState, useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import { api } from '../services/api';
import styles from './AIAssistantWidget.module.css';

/**
 * Format markdown text safely into React elements:
 * Handles bold text, bullet lists, numbered lists, and code blocks.
 */
function renderFormattedContent(text) {
  if (!text) return null;

  const lines = text.split('\n');
  const elements = [];
  let currentList = null;

  const parseInline = (lineText) => {
    const parts = lineText.split(/(\*\*.*?\*\*|`.*?`)/g);
    return parts.map((part, idx) => {
      if (part.startsWith('**') && part.endsWith('**')) {
        return <strong key={idx}>{part.slice(2, -2)}</strong>;
      }
      if (part.startsWith('`') && part.endsWith('`')) {
        return <code key={idx}>{part.slice(1, -1)}</code>;
      }
      return part;
    });
  };

  lines.forEach((line, index) => {
    const trimmed = line.trim();

    if (!trimmed) {
      if (currentList) {
        elements.push(
          <ul key={`list-${index}`} style={{ margin: '4px 0 8px 16px' }}>
            {currentList.map((item, i) => (
              <li key={i}>{parseInline(item)}</li>
            ))}
          </ul>
        );
        currentList = null;
      }
      return;
    }

    if (/^[•\-\*]\s+/.test(trimmed)) {
      const itemText = trimmed.replace(/^[•\-\*]\s+/, '');
      if (!currentList) currentList = [];
      currentList.push(itemText);
      return;
    }

    if (/^\d+\.\s+/.test(trimmed)) {
      if (currentList) {
        elements.push(
          <ul key={`list-${index}`} style={{ margin: '4px 0 8px 16px' }}>
            {currentList.map((item, i) => (
              <li key={i}>{parseInline(item)}</li>
            ))}
          </ul>
        );
        currentList = null;
      }
      const itemText = trimmed.replace(/^\d+\.\s+/, '');
      elements.push(
        <div key={`num-${index}`} style={{ margin: '3px 0 3px 6px', display: 'flex', gap: '6px' }}>
          <span style={{ fontWeight: 700, color: 'var(--kavach-quicksand, #E0C58F)' }}>
            {trimmed.match(/^\d+\./)[0]}
          </span>
          <span>{parseInline(itemText)}</span>
        </div>
      );
      return;
    }

    if (currentList) {
      elements.push(
        <ul key={`list-${index}`} style={{ margin: '4px 0 8px 16px' }}>
          {currentList.map((item, i) => (
            <li key={i}>{parseInline(item)}</li>
          ))}
        </ul>
      );
      currentList = null;
    }

    elements.push(
      <p key={`p-${index}`} style={{ margin: '0 0 6px' }}>
        {parseInline(trimmed)}
      </p>
    );
  });

  if (currentList) {
    elements.push(
      <ul key="list-final" style={{ margin: '4px 0 8px 16px' }}>
        {currentList.map((item, i) => (
          <li key={i}>{parseInline(item)}</li>
        ))}
      </ul>
    );
  }

  return elements;
}

const SAMPLE_PROMPTS = [
  {
    title: 'How does KAVACH protect against UPI and QR scams?',
    category: 'Payment Safety',
  },
  {
    title: 'What are the top warning signs of a phishing link or SMS?',
    category: 'Phishing Defense',
  },
  {
    title: 'Explain the difference between malware, ransomware, and spyware.',
    category: 'Cyber Defense',
  },
  {
    title: 'How do I secure my WhatsApp and social media accounts with 2FA?',
    category: 'Account Safety',
  },
];

export default function AIAssistantWidget() {
  const location = useLocation();

  // Widget States: 'collapsed' | 'panel' | 'fullscreen'
  const [widgetState, setWidgetState] = useState('collapsed');
  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const messagesEndRef = useRef(null);
  const textareaRef = useRef(null);

  // Derive human-readable page context based on route
  const getPageContext = () => {
    const p = location.pathname;
    if (p.includes('/user/messages')) return { name: 'Message Scam Detector', type: 'message' };
    if (p.includes('/user/link-checker')) return { name: 'Link Safety Checker', type: 'link' };
    if (p.includes('/user/document-checker')) return { name: 'Document Scanner', type: 'document' };
    if (p.includes('/user/qr-scanner')) return { name: 'QR Code Threat Scanner', type: 'document' };
    if (p.includes('/user/alerts')) return { name: 'Security Alerts', type: 'alerts' };
    if (p.includes('/user/guardian')) return { name: 'Guardian Access', type: 'guardian' };
    if (p.includes('/user/reports')) return { name: 'Incident Reports', type: 'reports' };
    if (p.includes('/user/security')) return { name: 'Security Center', type: 'security' };
    if (p.includes('/user/profile')) return { name: 'Profile & Settings', type: 'profile' };
    return { name: 'Dashboard Overview', type: 'dashboard' };
  };

  const pageContext = getPageContext();

  // Auto-scroll on new message
  useEffect(() => {
    if (widgetState !== 'collapsed') {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isLoading, widgetState]);

  // Focus textarea when panel opens
  useEffect(() => {
    if (widgetState !== 'collapsed') {
      setTimeout(() => textareaRef.current?.focus(), 80);
    }
  }, [widgetState]);

  const sendMessage = async (textToSend) => {
    const text = (textToSend || inputMessage).trim();
    if (!text || isLoading) return;

    const userMsg = {
      id: Date.now(),
      role: 'user',
      content: text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    const nextMessages = [...messages, userMsg];
    setMessages(nextMessages);
    setInputMessage('');
    setIsLoading(true);

    const historyPayload = messages.slice(-6).map((m) => ({
      role: m.role,
      content: m.content,
    }));

    try {
      const response = await api.chatWithAI({
        message: text,
        history: historyPayload,
        context: {
          active_page: pageContext.name,
          page_type: pageContext.type,
          route: location.pathname,
        },
      });

      const aiMsg = {
        id: Date.now() + 1,
        role: 'assistant',
        content: response.reply,
        source: response.source || 'kavach-knowledge-engine',
        model: response.model || 'kavach-expert-v1',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setMessages([...nextMessages, aiMsg]);
    } catch (err) {
      console.error('AI Widget Error:', err);
      const errMsg = {
        id: Date.now() + 1,
        role: 'assistant',
        content: '⚠️ Unable to connect to KAVACH AI assistant. Please verify that the backend server is active.',
        source: 'error',
        model: 'system',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages([...nextMessages, errMsg]);
    } finally {
      setIsLoading(false);
      setTimeout(() => textareaRef.current?.focus(), 50);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const handleResetChat = () => {
    setMessages([]);
  };

  // ── STATE 1: COLLAPSED TRIGGER ──
  if (widgetState === 'collapsed') {
    return (
      <button
        type="button"
        className={styles.floatingTrigger}
        onClick={() => setWidgetState('panel')}
        title="Open KAVACH AI Assistant"
      >
        <span className={styles.triggerIcon}>🛡️</span>
        <span>✦ KAVACH AI</span>
      </button>
    );
  }

  // ── STATE 2 & 3: PANEL OR FULL SCREEN ──
  const isFullScreen = widgetState === 'fullscreen';

  return (
    <div className={isFullScreen ? styles.fullScreenOverlay : styles.chatPanel}>
      {/* Widget Header */}
      <div className={styles.widgetHeader}>
        <div className={styles.headerTitleGroup}>
          <div className={styles.widgetBrand}>
            <span>🛡️ KAVACH AI</span>
            <span className={styles.brandPill}>24/7 DEFENSE</span>
          </div>
          <span className={styles.pageContextTag}>
            <span>Context:</span>
            <strong>{pageContext.name}</strong>
          </span>
        </div>

        <div className={styles.headerControlBtns}>
          {/* Reset Conversation */}
          <button
            type="button"
            className={styles.iconControlBtn}
            onClick={handleResetChat}
            title="Reset Conversation"
          >
            ↺
          </button>

          {/* Maximize / Restore */}
          {isFullScreen ? (
            <button
              type="button"
              className={styles.iconControlBtn}
              onClick={() => setWidgetState('panel')}
              title="Restore Panel View"
            >
              ⤓
            </button>
          ) : (
            <button
              type="button"
              className={styles.iconControlBtn}
              onClick={() => setWidgetState('fullscreen')}
              title="Maximize to Full Screen"
            >
              ⤢
            </button>
          )}

          {/* Close / Collapse */}
          <button
            type="button"
            className={styles.iconControlBtn}
            onClick={() => setWidgetState('collapsed')}
            title="Minimize Assistant"
          >
            ✕
          </button>
        </div>
      </div>

      {/* Messages Scroll Canvas */}
      <div className={styles.messagesScrollArea}>
        {messages.length === 0 && (
          <div className={styles.welcomeBanner}>
            <div className={styles.welcomeShield}>🛡️</div>
            <h3 className={styles.welcomeTitle}>KAVACH AI Assistant</h3>
            <p className={styles.welcomeSub}>
              Ask anything about scams, phishing, suspicious links, KAVACH features, or general topics.
            </p>

            <div className={styles.chipsGrid}>
              {SAMPLE_PROMPTS.map((p, idx) => (
                <button
                  key={idx}
                  type="button"
                  className={styles.chipBtn}
                  onClick={() => sendMessage(p.title)}
                >
                  <span className={styles.chipCategory}>{p.category}</span>
                  <span>{p.title}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg) => {
          const isUser = msg.role === 'user';
          return (
            <div
              key={msg.id}
              className={`${styles.messageRow} ${isUser ? styles.rowUser : styles.rowAssistant}`}
            >
              <div
                className={`${styles.bubble} ${
                  isUser ? styles.bubbleUser : styles.bubbleAssistant
                }`}
              >
                {!isUser && (
                  <div className={styles.bubbleMeta}>
                    <span style={{ fontWeight: 700, color: 'var(--kavach-quicksand, #E0C58F)' }}>
                      KAVACH AI
                    </span>
                    {msg.source && msg.source !== 'error' && (
                      <span className={styles.sourceBadge}>
                        {msg.source === 'ollama' ? 'Ollama' : 'Defense Engine'}
                      </span>
                    )}
                  </div>
                )}

                <div>{renderFormattedContent(msg.content)}</div>
                <span className={styles.timeFooter}>{msg.timestamp}</span>
              </div>
            </div>
          );
        })}

        {isLoading && (
          <div className={`${styles.messageRow} ${styles.rowAssistant}`}>
            <div className={styles.typingRow}>
              <div className={styles.typingDot} />
              <div className={styles.typingDot} />
              <div className={styles.typingDot} />
              <span className={styles.typingLabel}>KAVACH AI is thinking…</span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input Form Footer */}
      <div className={styles.inputFooter}>
        <form
          className={styles.inputForm}
          onSubmit={(e) => {
            e.preventDefault();
            sendMessage();
          }}
        >
          <textarea
            ref={textareaRef}
            className={styles.textInput}
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={`Ask KAVACH AI about ${pageContext.name} or general security…`}
            rows={1}
            disabled={isLoading}
          />
          <button
            type="submit"
            className={styles.sendBtn}
            disabled={isLoading || !inputMessage.trim()}
          >
            <span>Send</span>
            <span>➤</span>
          </button>
        </form>

        <div className={styles.inputHelperText}>
          <span>Enter to send • Shift+Enter for new line</span>
          <span>Zero-exposure privacy protected</span>
        </div>
      </div>
    </div>
  );
}
