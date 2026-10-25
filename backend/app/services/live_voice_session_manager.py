"""
=============================================================================
KAVACH — Live Voice Call Session Manager
=============================================================================
In-memory session manager for real-time two-person voice calls.
Enforces:
  - 2-person participant limit per call session
  - Ephemeral in-memory storage (privacy-first, no audio permanently stored)
  - WebRTC signaling routing (offer, answer, ICE candidates)
  - Live transcript buffer and rolling peak risk tracking
=============================================================================
"""

import datetime
import logging
import secrets
import string
import threading
import uuid
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("kavach.services.live_voice_session")


def generate_room_code() -> str:
    """Generates an intuitive, readable 6-character room code: e.g. KV-8492"""
    num_part = "".join(secrets.choice(string.digits) for _ in range(4))
    return f"KV-{num_part}"


class VoiceSession:
    def __init__(self, session_id: str, room_code: str, host_id: int, host_name: str):
        self.session_id: str = session_id
        self.room_code: str = room_code
        self.host_id: int = host_id
        self.host_name: str = host_name
        self.status: str = "WAITING"  # WAITING, ACTIVE, ENDED
        self.created_at: datetime.datetime = datetime.datetime.now(datetime.timezone.utc)
        self.ended_at: Optional[datetime.datetime] = None

        # Participants: list of dicts { user_id, user_name, joined_at, role: 'host' | 'peer' }
        self.participants: Dict[int, Dict[str, Any]] = {
            host_id: {
                "user_id": host_id,
                "user_name": host_name,
                "role": "host",
                "joined_at": self.created_at.isoformat(),
                "muted": False,
            }
        }

        # Ephemeral transcript buffer (bounded in-memory)
        self.transcripts: List[Dict[str, Any]] = []

        # Peak risk tracking for summary
        self.peak_risk_level: str = "SAFE"
        self.peak_risk_score: int = 0
        self.latest_risk_assessment: Dict[str, Any] = {
            "risk_level": "SAFE",
            "risk_score": 0,
            "detected_indicators": [],
            "reasons": ["Call session initialized. Waiting for conversation."],
            "recommended_action": "Speak normally. Live Guardian will monitor for scam patterns.",
            "summary": "Audio stream initialized.",
            "detected_language": "en",
        }

        # WebRTC signals queue/mailbox between peers
        self.signals: Dict[int, List[Dict[str, Any]]] = {host_id: []}

    def to_dict(self) -> Dict[str, Any]:
        duration_sec = 0
        if self.status == "ACTIVE":
            duration_sec = int((datetime.datetime.now(datetime.timezone.utc) - self.created_at).total_seconds())
        elif self.status == "ENDED" and self.ended_at:
            duration_sec = int((self.ended_at - self.created_at).total_seconds())

        return {
            "session_id": self.session_id,
            "room_code": self.room_code,
            "status": self.status,
            "participant_count": len(self.participants),
            "participants": list(self.participants.values()),
            "duration_seconds": max(0, duration_sec),
            "peak_risk_level": self.peak_risk_level,
            "peak_risk_score": self.peak_risk_score,
            "latest_risk": self.latest_risk_assessment,
            "transcript_count": len(self.transcripts),
            "created_at": self.created_at.isoformat(),
        }


class LiveVoiceSessionManager:
    """Thread-safe manager for all active in-memory voice sessions."""

    _instance: Optional["LiveVoiceSessionManager"] = None

    def __init__(self):
        self._sessions: Dict[str, VoiceSession] = {}
        self._code_to_id: Dict[str, str] = {}
        self._lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "LiveVoiceSessionManager":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def create_session(self, host_id: int, host_name: str, room_code: Optional[str] = None) -> VoiceSession:
        with self._lock:
            session_id = str(uuid.uuid4())
            code = (room_code or generate_room_code()).upper().strip()

            # Ensure code uniqueness
            while code in self._code_to_id:
                code = generate_room_code()

            session = VoiceSession(
                session_id=session_id,
                room_code=code,
                host_id=host_id,
                host_name=host_name
            )
            self._sessions[session_id] = session
            self._code_to_id[code] = session_id
            logger.info(f"Created voice session {session_id} with room code {code} by user {host_id}")
            return session

    def get_session(self, session_id_or_code: str) -> Optional[VoiceSession]:
        with self._lock:
            key = session_id_or_code.strip()
            if key in self._sessions:
                return self._sessions[key]
            if key.upper() in self._code_to_id:
                return self._sessions.get(self._code_to_id[key.upper()])
            return None

    def join_session(self, session_id_or_code: str, user_id: int, user_name: str) -> Tuple[bool, str, Optional[VoiceSession]]:
        with self._lock:
            key = session_id_or_code.strip()
            session = self._sessions.get(key) or self._sessions.get(self._code_to_id.get(key.upper(), ""))
            if not session:
                return False, "Voice session not found or has expired.", None

            if session.status == "ENDED":
                return False, "This voice session has already ended.", session

            # If user already in session, allow reconnecting
            if user_id in session.participants:
                session.participants[user_id]["user_name"] = user_name
                return True, "Reconnected to active voice session.", session

            # Enforce 2-person limit
            if len(session.participants) >= 2:
                return False, "Voice session is full (maximum 2 participants allowed).", session

            # Add second participant
            session.participants[user_id] = {
                "user_id": user_id,
                "user_name": user_name,
                "role": "peer",
                "joined_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "muted": False,
            }
            session.signals[user_id] = []
            if "pending_peer" in session.signals:
                session.signals[user_id].extend(session.signals.pop("pending_peer"))
            session.status = "ACTIVE"
            logger.info(f"User {user_id} ({user_name}) joined voice session {session.session_id}. Call now ACTIVE.")
            return True, "Successfully joined voice session.", session

    def add_signal(self, session_id: str, sender_id: int, signal_payload: Dict[str, Any]) -> bool:
        """Enqueues WebRTC signaling message (offer, answer, ice-candidate) to peer(s)."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session or session.status == "ENDED":
                return False

            target_id = signal_payload.get("target_id")
            forwarded = False
            for pid in session.participants:
                if pid != sender_id:
                    if target_id is None or target_id == pid:
                        session.signals.setdefault(pid, []).append({
                            "sender_id": sender_id,
                            "signal": signal_payload,
                            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        })
                        forwarded = True

            # If peer has not joined yet, queue for upcoming peer
            if not forwarded and len(session.participants) < 2 and target_id is None:
                session.signals.setdefault("pending_peer", []).append({
                    "sender_id": sender_id,
                    "signal": signal_payload,
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                })
            return True

    def get_pending_signals(self, session_id: str, user_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return []
            signals = session.signals.get(user_id, [])
            session.signals[user_id] = []
            return signals

    def record_transcript_and_risk(
        self,
        session_id: str,
        speaker_id: int,
        speaker_name: str,
        text: str,
        language: str,
        risk_result: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None

            timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
            turn = {
                "speaker_id": speaker_id,
                "speaker_name": speaker_name,
                "text": text,
                "language": language,
                "timestamp": timestamp,
                "risk_score": risk_result.get("risk_score", 0),
                "risk_level": risk_result.get("risk_level", "SAFE"),
            }
            session.transcripts.append(turn)
            # Cap in-memory history to last 50 turns
            if len(session.transcripts) > 50:
                session.transcripts.pop(0)

            # Update peak risk
            score = risk_result.get("risk_score", 0)
            if score > session.peak_risk_score:
                session.peak_risk_score = score
                session.peak_risk_level = risk_result.get("risk_level", "SAFE")

            session.latest_risk_assessment = risk_result
            return turn

    def end_session(self, session_id: str, ended_by_user_id: int) -> Tuple[bool, str, Optional[VoiceSession]]:
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False, "Session not found.", None

            session.status = "ENDED"
            session.ended_at = datetime.datetime.now(datetime.timezone.utc)
            logger.info(f"Voice session {session_id} ended by user {ended_by_user_id}.")
            return True, "Call session ended successfully.", session
