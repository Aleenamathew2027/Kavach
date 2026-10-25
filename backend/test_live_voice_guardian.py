"""
=============================================================================
KAVACH — Live Voice Guardian Test Suite
=============================================================================
Validates:
  1. English safe conversation
  2. English OTP scam
  3. English payment scam
  4. English impersonation
  5. Malayalam OTP scam
  6. Malayalam payment scam
  7. Malayalam-English mixed scam (Manglish)
  8. Normal Malayalam conversation
  9. Normal English conversation
  10. Empty transcript
  11. STT unavailable / fallback handling
  12. Unauthorized request / RBAC protection
  13. Risk score range (0-100) and risk categories
  14. Guardian privacy (sanitized alerts, no private transcript leakage)
  15. Two-person call session lifecycle & limit
=============================================================================
"""

import pytest
from fastapi.testclient import TestClient
from main import app
from app.services.live_voice_stt_service import (
    LiveVoiceSTTService,
    BuiltinSTTProvider,
    detect_transcript_language,
    transcribe_audio,
)
from app.services.live_voice_risk_service import LiveVoiceRiskService, analyze_voice_transcript
from app.services.live_voice_session_manager import LiveVoiceSessionManager
from app.utils.security import create_access_token
from app.models.user import User
from app.database.connection import SessionLocal

client = TestClient(app)


@pytest.fixture(scope="module")
def test_user_tokens():
    """Generates valid JWT tokens for test user 1 and test user 2."""
    db = SessionLocal()
    try:
        user1 = db.query(User).filter(User.email == "test_caller1@kavach.ai").first()
        if not user1:
            user1 = User(
                email="test_caller1@kavach.ai",
                full_name="Caller One",
                role="user",
                password="fakehashedpassword",
                auth_provider="local"
            )
            db.add(user1)
            db.commit()
            db.refresh(user1)

        user2 = db.query(User).filter(User.email == "test_caller2@kavach.ai").first()
        if not user2:
            user2 = User(
                email="test_caller2@kavach.ai",
                full_name="Caller Two",
                role="user",
                password="fakehashedpassword",
                auth_provider="local"
            )
            db.add(user2)
            db.commit()
            db.refresh(user2)

        token1 = create_access_token(data={"sub": str(user1.id), "role": "user"})
        token2 = create_access_token(data={"sub": str(user2.id), "role": "user"})
        admin_token = create_access_token(data={"sub": "999", "role": "admin"})

        return {
            "user1": user1,
            "user2": user2,
            "token1": token1,
            "token2": token2,
            "admin_token": admin_token,
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# UNIT TESTS: RISK SERVICE & LANGUAGE DETECTION
# ---------------------------------------------------------------------------

def test_language_detection():
    # Pure English
    assert detect_transcript_language("Hello, how are you doing today?") == "en"

    # Pure Malayalam script
    assert detect_transcript_language("നിങ്ങളുടെ ബാങ്ക് അക്കൗണ്ട് ബ്ലോക്ക് ആയിട്ടുണ്ട്.") == "ml"

    # Mixed Malayalam script + English
    assert detect_transcript_language("നിങ്ങളുടെ ബാങ്ക് അക്കൗണ്ട് block ആയിട്ടുണ്ട്. OTP തരൂ.") == "mixed"

    # Manglish / Mixed transliteration
    assert detect_transcript_language("Ningalude bank account block aayittundu. OTP paranju tharumo?") == "mixed"
    assert detect_transcript_language("Your account block aayi. Verification cheyyan OTP venam.") == "mixed"


def test_1_english_safe_conversation():
    text = "Good morning! Can we meet at the cafeteria around 2 PM to review the project report?"
    res = analyze_voice_transcript(text)
    assert res["risk_level"] == "SAFE"
    assert res["risk_score"] < 30
    assert len(res["detected_indicators"]) == 0
    assert "reasons" in res
    assert "recommended_action" in res


def test_2_english_otp_scam():
    text = "Your bank account has been blocked immediately. Please give me the OTP you received to verify."
    res = analyze_voice_transcript(text)
    assert res["risk_level"] == "HIGH RISK"
    assert res["risk_score"] >= 60
    assert any("OTP" in ind for ind in res["detected_indicators"])
    assert "recommended_action" in res


def test_3_english_payment_scam():
    text = "You must transfer the fine amount of 5000 rupees immediately via UPI or your account will be suspended."
    res = analyze_voice_transcript(text)
    assert res["risk_level"] in ("SUSPICIOUS", "HIGH RISK")
    assert res["risk_score"] >= 30
    assert any("Payment" in ind or "Urgent" in ind for ind in res["detected_indicators"])


def test_4_english_impersonation():
    text = "This is senior cyber crime police officer calling from head office regarding an urgent arrest warrant."
    res = analyze_voice_transcript(text)
    assert res["risk_score"] >= 30
    assert any("Impersonation" in ind or "Urgency" in ind for ind in res["detected_indicators"])


def test_5_malayalam_otp_scam():
    text = "നിങ്ങളുടെ ബാങ്ക് അക്കൗണ്ട് ബ്ലോക്ക് ആയിട്ടുണ്ട്. OTP ഒന്ന് പറഞ്ഞുതരൂ."
    res = analyze_voice_transcript(text)
    assert res["risk_level"] == "HIGH RISK"
    assert res["risk_score"] >= 60
    assert res["detected_language"] in ("ml", "mixed")
    assert any("OTP" in ind for ind in res["detected_indicators"])


def test_6_malayalam_payment_scam():
    text = "ഇപ്പോൾ തന്നെ പണം അയക്കൂ, അല്ലെങ്കിൽ അക്കൗണ്ട് മരവിപ്പിച്ചു കളയും."
    res = analyze_voice_transcript(text)
    assert res["risk_level"] in ("SUSPICIOUS", "HIGH RISK")
    assert res["risk_score"] >= 45
    assert any("Payment" in ind or "Urgency" in ind for ind in res["detected_indicators"])


def test_7_malayalam_english_mixed_scam():
    text = "Ningalude bank account block aayittundu. OTP paranju tharumo?"
    res = analyze_voice_transcript(text)
    assert res["risk_level"] == "HIGH RISK"
    assert res["risk_score"] >= 60
    assert res["detected_language"] == "mixed"
    assert any("OTP" in ind for ind in res["detected_indicators"])


def test_8_normal_malayalam_conversation():
    text = "നമസ്കാരം, എന്തൊക്കെയുണ്ട് വിശേഷം? നാളെ കോളേജിൽ വരുന്നുണ്ടോ?"
    res = analyze_voice_transcript(text)
    assert res["risk_level"] == "SAFE"
    assert res["risk_score"] < 30
    assert res["detected_language"] == "ml"


def test_9_normal_english_conversation():
    text = "Hello, are you coming to the seminar tomorrow morning? The weather is nice."
    res = analyze_voice_transcript(text)
    assert res["risk_level"] == "SAFE"
    assert res["risk_score"] < 30
    assert res["detected_language"] == "en"


def test_10_empty_transcript():
    res = analyze_voice_transcript("   ")
    assert res["risk_level"] == "SAFE"
    assert res["risk_score"] == 0
    assert res["detected_indicators"] == []


def test_11_stt_unavailable_and_fallback():
    stt = LiveVoiceSTTService.get_instance()
    # Test empty or invalid audio data handling gracefully
    res = stt.transcribe_audio(b"")
    assert res["text"] == ""
    assert res["confidence"] == 0.0

    # Test short corrupt bytes
    res_short = stt.transcribe_audio(b"x")
    assert res_short["text"] == ""


def test_risk_score_bounds_and_categories():
    # Any combination must be strictly within [0, 100]
    scenarios = [
        "Hello friend",
        "Your account is blocked",
        "Urgent bank manager police officer otp password transfer money immediately anydesk",
    ]
    for s in scenarios:
        res = analyze_voice_transcript(s)
        assert 0 <= res["risk_score"] <= 100
        if res["risk_score"] >= 60:
            assert res["risk_level"] == "HIGH RISK"
        elif res["risk_score"] >= 30:
            assert res["risk_level"] == "SUSPICIOUS"
        else:
            assert res["risk_level"] == "SAFE"


# ---------------------------------------------------------------------------
# INTEGRATION TESTS: FASTAPI ENDPOINTS & RBAC & GUARDIAN PRIVACY
# ---------------------------------------------------------------------------

def test_12_unauthorized_request():
    # Attempting to access without auth token must return 401
    resp = client.post("/voice/session/create")
    assert resp.status_code == 401

    resp2 = client.post("/voice/analyze", json={"text": "Hello"})
    assert resp2.status_code == 401


def test_session_lifecycle_and_two_person_limit(test_user_tokens):
    headers_u1 = {"Authorization": f"Bearer {test_user_tokens['token1']}"}
    headers_u2 = {"Authorization": f"Bearer {test_user_tokens['token2']}"}

    # 1. User 1 creates session
    create_res = client.post("/voice/session/create", headers=headers_u1, json={})
    assert create_res.status_code == 200
    data = create_res.json()
    session_id = data["session_id"]
    room_code = data["room_code"]
    assert room_code.startswith("KV-")
    assert data["status"] == "WAITING"

    # 2. User 2 joins using room_code
    join_res = client.post("/voice/session/join", headers=headers_u2, json={"room_code": room_code})
    assert join_res.status_code == 200
    join_data = join_res.json()
    assert join_data["status"] == "ACTIVE"
    assert join_data["participant_count"] == 2

    # 3. Third user attempt to join MUST be rejected (Max 2 participants)
    db = SessionLocal()
    user3 = db.query(User).filter(User.email == "test_caller3@kavach.ai").first()
    if not user3:
        user3 = User(
            email="test_caller3@kavach.ai",
            full_name="Caller Three",
            role="user",
            password="fakehashedpassword",
            auth_provider="local"
        )
        db.add(user3)
        db.commit()
        db.refresh(user3)
    token3 = create_access_token(data={"sub": str(user3.id), "role": "user"})
    db.close()

    headers_u3 = {"Authorization": f"Bearer {token3}"}
    reject_res = client.post("/voice/session/join", headers=headers_u3, json={"room_code": room_code})
    assert reject_res.status_code == 400
    assert "maximum 2 participants" in reject_res.json()["detail"].lower()

    # 4. Exchange WebRTC signal
    sig_res = client.post(
        f"/voice/session/signal/{session_id}",
        headers=headers_u1,
        json={"type": "offer", "payload": {"sdp": "fake-sdp-offer"}}
    )
    assert sig_res.status_code == 200

    # User 2 retrieves signal
    get_sig = client.get(f"/voice/session/signals/{session_id}", headers=headers_u2)
    assert get_sig.status_code == 200
    signals = get_sig.json()["signals"]
    assert len(signals) == 1
    assert signals[0]["signal"]["type"] == "offer"

    # 5. Live Speech Analysis & Guardian Privacy Verification
    analyze_payload = {
        "session_id": session_id,
        "text": "Your account has been blocked. Give me the OTP immediately.",
        "speaker": "Participant 1",
        "sync_guardian": True,
    }
    ana_res = client.post("/voice/analyze", headers=headers_u1, json=analyze_payload)
    assert ana_res.status_code == 200
    ana_data = ana_res.json()
    assert ana_data["risk_level"] == "HIGH RISK"
    assert ana_data["risk_score"] >= 60
    assert ana_data["guardian_alert_sent"] is True

    # 6. Verify Guardian Privacy: Alert in DB contains only sanitized info, NOT private conversation text
    db = SessionLocal()
    from app.models.security_alert import SecurityAlert
    alert = db.query(SecurityAlert).filter(
        SecurityAlert.user_id == test_user_tokens["user1"].id,
        SecurityAlert.alert_type == "voice_vishing_scam"
    ).order_by(SecurityAlert.id.desc()).first()
    assert alert is not None
    # Private full text must NOT be leaked directly into guardian message
    assert "Give me the OTP immediately" not in alert.message
    assert "Live Voice Guardian detected" in alert.message
    db.close()

    # 7. End Call
    end_res = client.post("/voice/session/end", headers=headers_u1, json={"session_id": session_id})
    assert end_res.status_code == 200
    end_data = end_res.json()
    assert end_data["status"] == "ENDED"
    assert end_data["peak_risk_level"] == "HIGH RISK"


# ---------------------------------------------------------------------------
# FOCUSED TESTS: TWO-WAY AUDIO/TRANSCRIPT, SIGNALING, MALAYALAM/MANGLISH
# ---------------------------------------------------------------------------

def test_two_participant_session_roles_and_state(test_user_tokens):
    headers_u1 = {"Authorization": f"Bearer {test_user_tokens['token1']}"}
    headers_u2 = {"Authorization": f"Bearer {test_user_tokens['token2']}"}

    # P1 creates call
    res1 = client.post("/voice/session/create", headers=headers_u1, json={})
    assert res1.status_code == 200
    d1 = res1.json()
    assert d1["your_role"] == "Participant 1"
    assert d1["status"] == "WAITING"
    room_code = d1["room_code"]
    session_id = d1["session_id"]

    # P2 joins call
    res2 = client.post("/voice/session/join", headers=headers_u2, json={"room_code": room_code})
    assert res2.status_code == 200
    d2 = res2.json()
    assert d2["your_role"] == "Participant 2"
    assert d2["status"] == "ACTIVE"
    assert d2["participant_count"] == 2


def test_participant_1_and_participant_2_two_way_transcripts(test_user_tokens):
    headers_u1 = {"Authorization": f"Bearer {test_user_tokens['token1']}"}
    headers_u2 = {"Authorization": f"Bearer {test_user_tokens['token2']}"}

    # 1. Create and Join session
    c_res = client.post("/voice/session/create", headers=headers_u1, json={})
    session_id = c_res.json()["session_id"]
    room_code = c_res.json()["room_code"]
    client.post("/voice/session/join", headers=headers_u2, json={"room_code": room_code})

    # 2. Participant 1 speaks
    turn1_payload = {
        "session_id": session_id,
        "text": "Hello, thank you for joining this voice call.",
        "speaker": "Participant 1",
        "language": "en",
        "sync_guardian": False,
    }
    ana1 = client.post("/voice/analyze", headers=headers_u1, json=turn1_payload)
    assert ana1.status_code == 200
    assert ana1.json()["risk_level"] == "SAFE"

    # 3. Participant 2 speaks
    turn2_payload = {
        "session_id": session_id,
        "text": "Yes, I am on the line. How can I assist you?",
        "speaker": "Participant 2",
        "language": "en",
        "sync_guardian": False,
    }
    ana2 = client.post("/voice/analyze", headers=headers_u2, json=turn2_payload)
    assert ana2.status_code == 200

    # 4. Verify both transcripts are preserved in session history without overwriting
    sess_res = client.get(f"/voice/session/{session_id}", headers=headers_u1)
    assert sess_res.status_code == 200
    sess_data = sess_res.json()
    assert sess_data["transcript_count"] == 2

    # Check session manager raw turns
    session_mgr = LiveVoiceSessionManager.get_instance()
    active_session = session_mgr.get_session(session_id)
    assert len(active_session.transcripts) == 2
    assert active_session.transcripts[0]["speaker_name"] == "Participant 1"
    assert active_session.transcripts[0]["text"] == turn1_payload["text"]
    assert active_session.transcripts[1]["speaker_name"] == "Participant 2"
    assert active_session.transcripts[1]["text"] == turn2_payload["text"]


def test_two_way_signaling_bidirectional(test_user_tokens):
    headers_u1 = {"Authorization": f"Bearer {test_user_tokens['token1']}"}
    headers_u2 = {"Authorization": f"Bearer {test_user_tokens['token2']}"}

    c_res = client.post("/voice/session/create", headers=headers_u1, json={})
    session_id = c_res.json()["session_id"]
    room_code = c_res.json()["room_code"]
    client.post("/voice/session/join", headers=headers_u2, json={"room_code": room_code})

    # P1 sends offer
    s1 = client.post(
        f"/voice/session/signal/{session_id}",
        headers=headers_u1,
        json={"type": "offer", "payload": {"sdp": "v=0\r\no=alice..."}}
    )
    assert s1.status_code == 200

    # P2 retrieves offer
    p2_sigs = client.get(f"/voice/session/signals/{session_id}", headers=headers_u2).json()["signals"]
    assert len(p2_sigs) == 1
    assert p2_sigs[0]["signal"]["type"] == "offer"

    # P2 sends answer
    s2 = client.post(
        f"/voice/session/signal/{session_id}",
        headers=headers_u2,
        json={"type": "answer", "payload": {"sdp": "v=0\r\no=bob..."}}
    )
    assert s2.status_code == 200

    # P1 retrieves answer
    p1_sigs = client.get(f"/voice/session/signals/{session_id}", headers=headers_u1).json()["signals"]
    assert len(p1_sigs) == 1
    assert p1_sigs[0]["signal"]["type"] == "answer"

    # P1 sends candidate
    client.post(
        f"/voice/session/signal/{session_id}",
        headers=headers_u1,
        json={"type": "candidate", "payload": {"candidate": "candidate:1 1 UDP..."}}
    )
    # P2 sends candidate
    client.post(
        f"/voice/session/signal/{session_id}",
        headers=headers_u2,
        json={"type": "candidate", "payload": {"candidate": "candidate:2 1 UDP..."}}
    )

    p2_cand = client.get(f"/voice/session/signals/{session_id}", headers=headers_u2).json()["signals"]
    p1_cand = client.get(f"/voice/session/signals/{session_id}", headers=headers_u1).json()["signals"]
    assert len(p2_cand) == 1
    assert p2_cand[0]["signal"]["payload"]["candidate"] == "candidate:1 1 UDP..."
    assert len(p1_cand) == 1
    assert p1_cand[0]["signal"]["payload"]["candidate"] == "candidate:2 1 UDP..."


def test_language_selection_handling():
    # Validates language detection and hint handling
    assert detect_transcript_language("Hello bank officer", hint_language="en") == "en"
    assert detect_transcript_language("നിങ്ങളുടെ അക്കൗണ്ട്", hint_language="ml") == "ml"
    assert detect_transcript_language("Account block aayi OTP tharumo", hint_language="mixed") == "mixed"
    # When text is empty, returns hint
    assert detect_transcript_language("", hint_language="ml") == "ml"
    assert detect_transcript_language("", hint_language="en") == "en"


def test_malayalam_risk_analysis_scenarios():
    # Malayalam OTP harvest
    ml_scam = "നിങ്ങളുടെ ബാങ്ക് അക്കൗണ്ട് ബ്ലോക്ക് ആയിട്ടുണ്ട്. OTP ഒന്ന് പറഞ്ഞുതരൂ."
    res = analyze_voice_transcript(ml_scam, speaker="Participant 2", language="ml")
    assert res["risk_level"] == "HIGH RISK"
    assert res["risk_score"] >= 60
    assert res["detected_language"] in ("ml", "mixed")

    # Safe Malayalam speech
    ml_safe = "നമസ്കാരം, എന്തൊക്കെയുണ്ട് വിശേഷം? സുഖമാണോ?"
    res_safe = analyze_voice_transcript(ml_safe, speaker="Participant 1", language="ml")
    assert res_safe["risk_level"] == "SAFE"
    assert res_safe["risk_score"] < 30


def test_manglish_risk_analysis_scenarios():
    # Manglish OTP and account threat
    manglish_scam = "Ningalude account block aayittundu. OTP paranju tharumo?"
    res = analyze_voice_transcript(manglish_scam, speaker="Participant 2", language="mixed")
    assert res["risk_level"] == "HIGH RISK"
    assert res["risk_score"] >= 60
    assert res["detected_language"] == "mixed"

    # Manglish urgent money demand
    manglish_pay = "Ippol thanne paisa transfer cheyyanam, illenkil case edukkum."
    res_pay = analyze_voice_transcript(manglish_pay, speaker="Participant 1", language="mixed")
    assert res_pay["risk_level"] in ("SUSPICIOUS", "HIGH RISK")
    assert res_pay["risk_score"] >= 45


def test_risk_analysis_from_participant_2_updates_overall_session(test_user_tokens):
    headers_u1 = {"Authorization": f"Bearer {test_user_tokens['token1']}"}
    headers_u2 = {"Authorization": f"Bearer {test_user_tokens['token2']}"}

    c_res = client.post("/voice/session/create", headers=headers_u1, json={})
    session_id = c_res.json()["session_id"]
    room_code = c_res.json()["room_code"]
    client.post("/voice/session/join", headers=headers_u2, json={"room_code": room_code})

    # Participant 1 says something normal
    client.post(
        "/voice/analyze",
        headers=headers_u1,
        json={"session_id": session_id, "text": "Hello, who is calling?", "speaker": "Participant 1"}
    )

    # Participant 2 says a vishing scam phrase
    p2_scam_payload = {
        "session_id": session_id,
        "text": "This is cyber police officer calling. Your bank account is blocked. Send OTP immediately.",
        "speaker": "Participant 2",
        "language": "en",
        "sync_guardian": False,
    }
    p2_res = client.post("/voice/analyze", headers=headers_u2, json=p2_scam_payload)
    assert p2_res.status_code == 200
    p2_data = p2_res.json()
    assert p2_data["risk_level"] == "HIGH RISK"
    assert p2_data["risk_score"] >= 60

    # Verify session detail reflects peak risk from Participant 2
    session_info = client.get(f"/voice/session/{session_id}", headers=headers_u1).json()
    assert session_info["peak_risk_level"] == "HIGH RISK"
    assert session_info["peak_risk_score"] >= 60
    assert session_info["latest_risk"]["risk_level"] == "HIGH RISK"
