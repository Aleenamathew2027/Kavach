import { useState, useRef, useEffect } from 'react';
import { guardianChatService } from '../services/guardianChatService';
import styles from './VoiceMessagePlayer.module.css';

export default function VoiceMessagePlayer({ messageId, duration = 0, isOwn = false }) {
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [totalDuration, setTotalDuration] = useState(duration || 0);
  const [audioUrl, setAudioUrl] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const audioRef = useRef(null);

  useEffect(() => {
    let active = true;
    let createdUrl = null;

    async function loadAudio() {
      try {
        setLoading(true);
        const blob = await guardianChatService.fetchVoiceBlob(messageId);
        if (!active) return;
        createdUrl = URL.createObjectURL(blob);
        setAudioUrl(createdUrl);
      } catch (err) {
        if (!active) return;
        console.warn('Voice message load notice:', err);
        setError('Voice note unavailable');
      } finally {
        if (active) setLoading(false);
      }
    }

    loadAudio();

    return () => {
      active = false;
      if (createdUrl) URL.revokeObjectURL(createdUrl);
    };
  }, [messageId]);

  const togglePlay = () => {
    if (!audioRef.current) return;
    if (isPlaying) {
      audioRef.current.pause();
      setIsPlaying(false);
    } else {
      audioRef.current.play().then(() => {
        setIsPlaying(true);
      }).catch((e) => {
        console.warn('Audio playback error:', e);
      });
    }
  };

  const handleTimeUpdate = () => {
    if (audioRef.current) {
      setCurrentTime(audioRef.current.currentTime);
      if (audioRef.current.duration && !isNaN(audioRef.current.duration)) {
        setTotalDuration(audioRef.current.duration);
      }
    }
  };

  const handleEnded = () => {
    setIsPlaying(false);
    setCurrentTime(0);
  };

  const handleSeek = (e) => {
    const seekTime = parseFloat(e.target.value);
    if (audioRef.current) {
      audioRef.current.currentTime = seekTime;
      setCurrentTime(seekTime);
    }
  };

  const formatSec = (seconds) => {
    const s = Math.floor(seconds || 0);
    const mins = Math.floor(s / 60);
    const rem = s % 60;
    return `${mins}:${String(rem).padStart(2, '0')}`;
  };

  const progressPercent = totalDuration > 0 ? (currentTime / totalDuration) * 100 : 0;

  if (error) {
    return <div className={styles.errorText}>⚠ {error}</div>;
  }

  return (
    <div className={`${styles.playerContainer} ${isOwn ? styles.playerOwn : styles.playerPeer}`}>
      {audioUrl && (
        <audio
          ref={audioRef}
          src={audioUrl}
          onTimeUpdate={handleTimeUpdate}
          onEnded={handleEnded}
          onLoadedMetadata={() => {
            if (audioRef.current?.duration && !isNaN(audioRef.current.duration)) {
              setTotalDuration(audioRef.current.duration);
            }
          }}
          preload="metadata"
        />
      )}

      <button
        type="button"
        className={styles.playBtn}
        onClick={togglePlay}
        disabled={loading || !audioUrl}
        aria-label={isPlaying ? 'Pause voice message' : 'Play voice message'}
      >
        {loading ? '⌛' : isPlaying ? '⏸' : '▶'}
      </button>

      <div className={styles.waveformArea}>
        <div className={styles.scrubberWrap}>
          <div className={styles.progressTrack} style={{ width: `${progressPercent}%` }} />
          <input
            type="range"
            min={0}
            max={totalDuration || 1}
            step={0.1}
            value={currentTime}
            onChange={handleSeek}
            className={styles.rangeInput}
            aria-label="Seek voice message position"
          />
        </div>

        <div className={styles.timeRow}>
          <span>{isPlaying ? formatSec(currentTime) : '🎤 Voice Message'}</span>
          <span>{formatSec(totalDuration || duration)}</span>
        </div>
      </div>
    </div>
  );
}
