from app.models import AuditLog
from sqlalchemy.orm import Session
from datetime import datetime
import uuid

def log_auth_attempt(user_id: str, action: str, db: Session, success: bool, metadata: dict = {}):
    log = AuditLog(
        id=str(uuid.uuid4()),
        actor_id=user_id,
        action=action,
        target=user_id,
        event_metadata={"success": success, **metadata},
        timestamp=datetime.utcnow()
    )
    db.add(log)
    db.commit()
