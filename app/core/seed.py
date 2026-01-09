from sqlalchemy.orm import Session
from app.models import Organization
from app.core.constants import DEFAULT_ORG_ID, DEFAULT_ORG_NAME

def seed_default_org(db: Session):
    org = db.query(Organization).filter(
        Organization.id == DEFAULT_ORG_ID
    ).first()

    if not org:
        org = Organization(
            id=DEFAULT_ORG_ID,
            name=DEFAULT_ORG_NAME
        )
        db.add(org)
        db.commit()
