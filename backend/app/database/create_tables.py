from app.database.base import Base
from app.database.connection import engine

# Import every model here
import app.models.user
import app.models.guardian
import app.models.security_scan
import app.models.security_alert
import app.models.incident_report
import app.models.ai_conversation
import app.models.ai_message
import app.models.user_feedback
import app.models.security_action
import app.models.security_preference
import app.models.scan_feedback
import app.models.threat_location

Base.metadata.create_all(bind=engine)

print("Tables created successfully!")
