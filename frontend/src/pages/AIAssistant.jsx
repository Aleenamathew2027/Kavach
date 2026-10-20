import { useState, useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import { api, getRole } from '../services/api';
import GuardianLayout from '../components/GuardianLayout';
import UserLayout from '../components/UserLayout';
import styles from './AIAssistant.module.css';

/**
 * Format markdown text safely into React elements:
 * Handles headers, bold text, bullet lists, numbered lists, and code blocks.
 */
function renderFormattedContent(text) {
  if (!text) return null;

  const lines = text.split('\n');
  const elements = [];
  let currentList = null;

  const parseInline = (lineText) => {
    // Splits text by bold **text** and code `code`
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
          <ul key={`list-${index}`} style={{ margin: '6px 0 10px 18px' }}>
            {currentList.map((item, i) => (
              <li key={i}>{parseInline(item)}</li>
            ))}
          </ul>
        );
        currentList = null;
      }
      return;
    }

    // Bullet points (• or - or *)
    if (/^[•\-\*]\s+/.test(trimmed)) {
      const itemText = trimmed.replace(/^[•\-\*]\s+/, '');
      if (!currentList) currentList = [];
      currentList.push(itemText);
      return;
    }

    // Numbered lists (1. 2.)
    if (/^\d+\.\s+/.test(trimmed)) {
      if (currentList) {
        elements.push(
          <ul key={`list-${index}`} style={{ margin: '6px 0 10px 18px' }}>
            {currentList.map((item, i) => (
              <li key={i}>{parseInline(item)}</li>
            ))}
          </ul>
        );
        currentList = null;
      }
      const itemText = trimmed.replace(/^\d+\.\s+/, '');
      elements.push(
        <div key={`num-${index}`} style={{ margin: '4px 0 4px 8px', display: 'flex', gap: '8px' }}>
          <span style={{ fontWeight: 700, opacity: 0.8 }}>{trimmed.match(/^\d+\./)[0]}</span>
          <span>{parseInline(itemText)}</span>
        </div>
      );
      return;
    }

    // Normal paragraph or section header
    if (currentList) {
      elements.push(
        <ul key={`list-${index}`} style={{ margin: '6px 0 10px 18px' }}>
          {currentList.map((item, i) => (
            <li key={i}>{parseInline(item)}</li>
          ))}
        </ul>
      );
      currentList = null;
    }

    elements.push(
      <p key={`p-${index}`} style={{ margin: '0 0 8px' }}>
        {parseInline(trimmed)}
      </p>
    );
  });

  if (currentList) {
    elements.push(
      <ul key="list-final" style={{ margin: '6px 0 10px 18px' }}>
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
    tag: 'Payment Fraud',
  },
  {
    title: 'What are the tell-tale warning signs of a phishing link or SMS?',
    tag: 'Phishing',
  },
  {
    title: 'Explain the difference between malware, ransomware, and spyware.',
    tag: 'Malware',
  },
  {
    title: 'How do I secure my WhatsApp and social media accounts with 2FA?',
    tag: 'Account Safety',
  },
];

export default function AIAssistant({ role: propRole }) {
  const location = useLocation();
  const currentRole = propRole || getRole() || 'user';
  const isGuardian = currentRole === 'guardian';

  const [userName, setUserName] = useState('');
  const [guardedUserName, setGuardedUserName] = useState('');
  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errorBanner, setErrorBanner] = useState(null);

  const messagesEndRef = useRef(null);
  const textareaRef = useRef(null);

  // Load user details for navigation bar
  useEffect(() => {
    if (isGuardian) {
      api.getGuardianDashboard()
        .then((data) => {
          if (data?.guarded_user?.full_name) {
            setGuardedUserName(data.guarded_user.full_name);
          }
        })
        .catch(() => null);
    } else {
      api.getMe()
        .then((data) => {
          if (data?.full_name) {
            setUserName(data.full_name);
          }
        })
        .catch(() => null);
    }
  }, [isGuardian]);

  // Handle incoming scan context from location state if any
  useEffect(() => {
    if (location.state?.scanContext) {
      const ctx = location.state.scanContext;
      const initialPrompt = `I just ran a ${ctx.scan_type || 'security scan'} which flagged a ${ctx.risk_level || 'warning'}. What should I do?`;
      sendMessage(initialPrompt, ctx);
    }
  }, [location.state]);

  // Auto-scroll on new message
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isLoading]);

  const sendMessage = async (textToSend, customContext = null) => {
    const text = (textToSend || inputMessage).trim();
    if (!text || isLoading) return;

    setErrorBanner(null);
    const userMsgId = Date.now();
    const newUserMsg = {
      id: userMsgId,
      role: 'user',
      content: text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    const nextMessages = [...messages, newUserMsg];
    setMessages(nextMessages);
    setInputMessage('');
    setIsLoading(true);

    // Format conversation history for backend
    const historyPayload = messages.slice(-8).map((m) => ({
      role: m.role,
      content: m.content,
    }));

    try {
      const response = await api.chatWithAI({
        message: text,
        history: historyPayload,
        context: customContext || location.state?.scanContext || null,
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
      console.error('AI Assistant Error:', err);
      const errMsg = err?.message || 'Unable to connect to KAVACH AI service. Please ensure the backend is running.';
      setErrorBanner(errMsg);
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

  const handleClearChat = () => {
    setMessages([]);
    setErrorBanner(null);
  };

  const formatSourceBadge = (source, model) => {
    if (source === 'ollama') {
      return `Ollama • ${model}`;
    }
    return 'KAVACH Defense Engine';
  };

  const chatContent = (
    <div className={styles.chatContainer}>
          <div className={styles.messagesArea}>
            {/* Empty State / Welcome Screen */}
            {messages.length === 0 && (
              <div className={styles.welcomeScreen}>
                <div className={styles.welcomeIconWrapper}>🛡️</div>
                <h2 className={styles.welcomeHeading}>How can KAVACH protect you today?</h2>
                <p className={styles.welcomeText}>
                  Ask any question regarding suspicious messages, fraudulent links, payment safety,
                  how KAVACH features work, or general inquiries. Select a prompt below or start typing.
                </p>

                <div className={styles.promptGridTitle}>Recommended Cyber Defense Queries</div>
                <div className={styles.promptGrid}>
                  {SAMPLE_PROMPTS.map((prompt, idx) => (
                    <button
                      key={idx}
                      className={styles.promptCard}
                      onClick={() => sendMessage(prompt.title)}
                      type="button"
                    >
                      <span className={styles.promptCardTag}>{prompt.tag}</span>
                      <span className={styles.promptCardTitle}>{prompt.title}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Conversation Messages */}
            {messages.map((msg) => {
              const isUser = msg.role === 'user';
              return (
                <div
                  key={msg.id}
                  className={`${styles.messageRow} ${isUser ? styles.rowUser : styles.rowAssistant}`}
                >
                  <div
                    className={`${styles.avatar} ${isUser ? styles.avatarUser : styles.avatarAssistant}`}
                  >
                    {isUser ? (isGuardian ? 'G' : 'U') : '🛡️'}
                  </div>

                  <div
                    className={`${styles.bubble} ${isUser ? styles.bubbleUser : styles.bubbleAssistant}`}
                  >
                    <div className={`${styles.bubbleMeta} ${!isGuardian && !isUser ? styles.bubbleMetaDark : ''}`}>
                      <span className={styles.senderName}>
                        {isUser ? (isGuardian ? 'Guardian' : 'You') : 'KAVACH AI'}
                      </span>
                      {!isUser && msg.source && (
                        <span className={styles.sourceBadge}>
                          {formatSourceBadge(msg.source, msg.model)}
                        </span>
                      )}
                    </div>

                    <div className={styles.bubbleContent}>
                      {renderFormattedContent(msg.content)}
                    </div>

                    <span className={styles.timeFooter}>{msg.timestamp}</span>
                  </div>
                </div>
              );
            })}

            {/* Thinking / Typing Indicator */}
            {isLoading && (
              <div className={`${styles.messageRow} ${styles.rowAssistant}`}>
                <div className={`${styles.avatar} ${styles.avatarAssistant}`}>🛡️</div>
                <div className={`${styles.bubble} ${styles.bubbleAssistant}`}>
                  <div className={styles.typingIndicator}>
                    <div className={styles.dot} />
                    <div className={styles.dot} />
                    <div className={styles.dot} />
                    <span className={styles.typingLabel}>KAVACH AI is thinking...</span>
                  </div>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Error Banner */}
          {errorBanner && (
            <div className={styles.errorBanner}>
              <span>{errorBanner}</span>
              <button
                className={styles.retryBtn}
                onClick={() => sendMessage()}
                type="button"
              >
                Retry
              </button>
            </div>
          )}

          {/* Input Form Area */}
          <form
            className={styles.inputForm}
            onSubmit={(e) => {
              e.preventDefault();
              sendMessage();
            }}
          >
            <div className={styles.inputWrapper}>
              <textarea
                ref={textareaRef}
                className={styles.textarea}
                placeholder={
                  isGuardian
                    ? 'Ask a question about security alerts, scam guidance, or KAVACH safeguards...'
                    : 'Ask about scam messages, suspicious links, digital safety, or general questions...'
                }
                value={inputMessage}
                onChange={(e) => setInputMessage(e.target.value)}
                onKeyDown={handleKeyDown}
                rows={1}
                disabled={isLoading}
              />
            </div>

            <button
              className={styles.sendBtn}
              type="submit"
              disabled={isLoading || !inputMessage.trim()}
            >
              <span>Send</span>
              <span>➤</span>
            </button>
          </form>

          <div className={styles.inputHelp}>
            <span>Press <strong>Enter</strong> to send, <strong>Shift + Enter</strong> for a new line</span>
            <span>Zero-exposure privacy protected</span>
          </div>
    </div>
  );

  if (!isGuardian) {
    return (
      <UserLayout
        eyebrow="AI CYBER INTELLIGENCE"
        title="KAVACH AI ASSISTANT"
        subtitle="24/7 intelligent assistance for cybersecurity defense, scam identification, KAVACH features, and general inquiries."
        headerAction={
          <button
            className={styles.clearBtn}
            onClick={handleClearChat}
            disabled={messages.length === 0 || isLoading}
            title="Clear conversation history"
          >
            <span>↺</span>
            <span>Reset Chat</span>
          </button>
        }
      >
        <div className={`${styles.page} ${styles.themeUser}`} style={{ minHeight: 'auto', background: 'transparent', padding: 0 }}>
          {chatContent}
        </div>
      </UserLayout>
    );
  }

  return (
    <GuardianLayout>
      <div className={`${styles.page} ${styles.themeGuardian}`} style={{ minHeight: 'auto', background: 'transparent' }}>
        <main className={styles.main}>
          <div className={styles.headerBar}>
            <div className={styles.headerLeft}>
              <div className={styles.badgePill}>
                <span className={styles.onlineDot} />
                <span>AI DIGITAL DEFENSE ASSISTANT</span>
              </div>
              <h1 className={styles.title}>KAVACH AI ASSISTANT</h1>
              <p className={styles.subtitle}>
                Assisting Guardian mode with threat intelligence and cybersecurity guidance for {guardedUserName || 'protected user'}.
              </p>
            </div>

            <div className={styles.headerActions}>
              <button
                className={styles.clearBtn}
                onClick={handleClearChat}
                disabled={messages.length === 0 || isLoading}
                title="Clear conversation history"
              >
                <span>↺</span>
                <span>Reset Chat</span>
              </button>
            </div>
          </div>

          {chatContent}
        </main>
      </div>
    </GuardianLayout>
  );
}
