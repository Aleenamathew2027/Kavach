import pytest
import secrets
from datetime import datetime, timezone
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database.connection import engine, SessionLocal
from app.database.init_db import init_db
from app.models.user import User
from app.models.security_scan import SecurityScan
from app.models.security_alert import SecurityAlert
from app.models.guardian import GuardianAccess
from app.models.incident_report import IncidentReport
from app.models.ai_conversation import AIConversation
from app.models.ai_message import AIMessage
from app.models.user_feedback import UserFeedback
from app.models.security_action import SecurityAction
from app.models.security_preference import SecurityPreference
from app.models.scan_feedback import ScanFeedback


@pytest.fixture(scope="module")
def db_session():
    init_db()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="module")
def inspector():
    return inspect(engine)


class TestDatabaseTablesPhase17:
    """Comprehensive test suite verifying the 6 new PostgreSQL tables and 5 existing tables."""

    def test_01_all_11_tables_exist(self, inspector):
        expected_tables = {
            "users",
            "security_scans",
            "security_alerts",
            "guardian_access",
            "incident_reports",
            "ai_conversations",
            "ai_messages",
            "user_feedback",
            "security_actions",
            "security_preferences",
            "scan_feedback",
        }
        actual_tables = set(inspector.get_table_names())
        assert expected_tables.issubset(actual_tables), (
            f"Missing tables: {expected_tables - actual_tables}"
        )
        assert len(actual_tables) >= 11

    def test_02_new_tables_have_expected_columns(self, inspector):
        expected_columns = {
            "ai_conversations": {"id", "user_id", "title", "context_type", "created_at", "updated_at"},
            "ai_messages": {"id", "conversation_id", "sender_type", "message", "created_at"},
            "user_feedback": {"id", "user_id", "feedback_type", "message", "rating", "created_at"},
            "security_actions": {
                "id",
                "user_id",
                "security_alert_id",
                "security_scan_id",
                "action_type",
                "action_status",
                "created_at",
            },
            "security_preferences": {
                "id",
                "user_id",
                "alert_notifications",
                "guardian_notifications",
                "high_risk_alerts",
                "email_notifications",
                "auto_incident_reports",
                "created_at",
                "updated_at",
            },
            "scan_feedback": {"id", "user_id", "security_scan_id", "actual_result", "comment", "created_at"},
        }

        for table_name, expected_cols in expected_columns.items():
            actual_cols = {col["name"] for col in inspector.get_columns(table_name)}
            assert expected_cols.issubset(actual_cols), (
                f"Table '{table_name}' is missing columns: {expected_cols - actual_cols}"
            )

    def test_03_foreign_keys_point_to_correct_tables(self, inspector):
        fk_checks = {
            "ai_conversations": [("user_id", "users", "id")],
            "ai_messages": [("conversation_id", "ai_conversations", "id")],
            "user_feedback": [("user_id", "users", "id")],
            "security_actions": [
                ("user_id", "users", "id"),
                ("security_alert_id", "security_alerts", "id"),
                ("security_scan_id", "security_scans", "id"),
            ],
            "security_preferences": [("user_id", "users", "id")],
            "scan_feedback": [
                ("user_id", "users", "id"),
                ("security_scan_id", "security_scans", "id"),
            ],
        }

        for table_name, expected_fks in fk_checks.items():
            actual_fks = inspector.get_foreign_keys(table_name)
            for constrained_col, referred_tbl, referred_col in expected_fks:
                matched = any(
                    fk["constrained_columns"] == [constrained_col]
                    and fk["referred_table"] == referred_tbl
                    and fk["referred_columns"] == [referred_col]
                    for fk in actual_fks
                )
                assert matched, (
                    f"Table '{table_name}' missing FK from '{constrained_col}' -> '{referred_tbl}.{referred_col}'. Found: {actual_fks}"
                )

    def test_04_security_preferences_user_id_unique(self, db_session: Session):
        test_id = secrets.token_hex(4)
        user = User(
            full_name=f"Pref Test User {test_id}",
            email=f"pref_test_{test_id}@kavach.ai",
            role="user",
            auth_provider="local",
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        pref1 = SecurityPreference(
            user_id=user.id,
            alert_notifications=True,
            guardian_notifications=True,
            high_risk_alerts=True,
            email_notifications=False,
            auto_incident_reports=True,
        )
        db_session.add(pref1)
        db_session.commit()

        # Duplicate user_id must raise IntegrityError
        pref2 = SecurityPreference(
            user_id=user.id,
            alert_notifications=False,
            guardian_notifications=False,
        )
        db_session.add(pref2)
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()

    def test_05_ai_conversations_belong_to_user(self, db_session: Session):
        test_id = secrets.token_hex(4)
        user = User(
            full_name=f"AI Conv User {test_id}",
            email=f"aiconv_{test_id}@kavach.ai",
            role="user",
            auth_provider="local",
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        conv = AIConversation(
            user_id=user.id,
            title="Suspicious WhatsApp Message Analysis",
            context_type="SECURITY",
        )
        db_session.add(conv)
        db_session.commit()
        db_session.refresh(conv)

        assert conv.id is not None
        assert conv.user_id == user.id
        assert conv.user.email == user.email
        assert conv in user.ai_conversations

    def test_06_ai_messages_belong_to_ai_conversation(self, db_session: Session):
        test_id = secrets.token_hex(4)
        user = User(
            full_name=f"Msg Test User {test_id}",
            email=f"msg_test_{test_id}@kavach.ai",
            role="user",
            auth_provider="local",
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        conv = AIConversation(
            user_id=user.id,
            title="OTP Scam Consultation",
            context_type="GENERAL",
        )
        db_session.add(conv)
        db_session.commit()
        db_session.refresh(conv)

        msg1 = AIMessage(
            conversation_id=conv.id,
            sender_type="USER",
            message="Someone asked for an OTP from bank. Should I give it?",
        )
        msg2 = AIMessage(
            conversation_id=conv.id,
            sender_type="ASSISTANT",
            message="Never share your OTP with anyone. Legitimate banks will never ask for your OTP.",
        )
        db_session.add_all([msg1, msg2])
        db_session.commit()
        db_session.refresh(conv)

        assert len(conv.messages) == 2
        assert conv.messages[0].sender_type == "USER"
        assert conv.messages[1].sender_type == "ASSISTANT"
        assert conv.messages[0].conversation.id == conv.id

    def test_07_security_actions_reference_alert_and_scan(self, db_session: Session):
        test_id = secrets.token_hex(4)
        user = User(
            full_name=f"Action Test User {test_id}",
            email=f"action_test_{test_id}@kavach.ai",
            role="user",
            auth_provider="local",
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        scan = SecurityScan(
            user_id=user.id,
            scan_type="link",
            input_reference="http://fake-login-bank.xyz",
            risk_level="HIGH RISK",
            risk_score=95,
            result_summary="Known phishing domain targeting credentials.",
        )
        alert = SecurityAlert(
            user_id=user.id,
            alert_type="link_scam",
            title="High-Risk Link Flagged",
            message="Phishing portal detected.",
            severity="HIGH",
        )
        db_session.add_all([scan, alert])
        db_session.commit()
        db_session.refresh(scan)
        db_session.refresh(alert)

        action = SecurityAction(
            user_id=user.id,
            security_alert_id=alert.id,
            security_scan_id=scan.id,
            action_type="BLOCKED",
            action_status="COMPLETED",
        )
        db_session.add(action)
        db_session.commit()
        db_session.refresh(action)

        assert action.id is not None
        assert action.security_alert_id == alert.id
        assert action.security_scan_id == scan.id
        assert action.security_alert.title == "High-Risk Link Flagged"
        assert action.security_scan.risk_level == "HIGH RISK"

    def test_08_scan_feedback_references_correct_security_scan(self, db_session: Session):
        test_id = secrets.token_hex(4)
        user = User(
            full_name=f"Feedback User {test_id}",
            email=f"feedback_user_{test_id}@kavach.ai",
            role="user",
            auth_provider="local",
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        scan = SecurityScan(
            user_id=user.id,
            scan_type="message",
            input_reference="Electricity bill overdue notification",
            risk_level="HIGH RISK",
            risk_score=90,
            result_summary="Urgent power cut extortion scam.",
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        fb = ScanFeedback(
            user_id=user.id,
            security_scan_id=scan.id,
            actual_result="CORRECT",
            comment="Definitely a scam message asking to call an unknown number.",
        )
        db_session.add(fb)
        db_session.commit()
        db_session.refresh(fb)

        assert fb.id is not None
        assert fb.security_scan_id == scan.id
        assert fb.security_scan.input_reference == "Electricity bill overdue notification"
        assert fb.actual_result == "CORRECT"

    def test_09_user_feedback_creation_and_rating_check(self, db_session: Session):
        test_id = secrets.token_hex(4)
        user = User(
            full_name=f"User Feedback {test_id}",
            email=f"user_feedback_{test_id}@kavach.ai",
            role="user",
            auth_provider="local",
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        fb = UserFeedback(
            user_id=user.id,
            feedback_type="SCAM_REPORT",
            message="Suspicious SMS impersonating government lottery.",
            rating=5,
        )
        db_session.add(fb)
        db_session.commit()
        db_session.refresh(fb)

        assert fb.id is not None
        assert fb.rating == 5
        assert fb.user.id == user.id

    def test_10_existing_5_tables_still_exist_and_intact(self, inspector):
        existing_5 = [
            ("users", ["id", "full_name", "email", "password", "role"]),
            ("security_scans", ["id", "user_id", "scan_type", "risk_level", "risk_score"]),
            ("security_alerts", ["id", "user_id", "alert_type", "title", "severity", "is_read"]),
            ("guardian_access", ["id", "user_id", "code_hash", "is_active", "expires_at"]),
            ("incident_reports", ["id", "report_id", "user_id", "incident_type", "risk_level"]),
        ]

        for table_name, key_cols in existing_5:
            assert inspector.has_table(table_name), f"Existing table '{table_name}' missing!"
            actual_cols = {c["name"] for c in inspector.get_columns(table_name)}
            for col in key_cols:
                assert col in actual_cols, f"Column '{col}' missing from existing table '{table_name}'!"
