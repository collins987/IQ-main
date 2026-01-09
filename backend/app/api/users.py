from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session
from app.schemas.user import UserCreate
from app.core.db import SessionLocal
from app.models import User, AuditLog
from app.core.security import hash_password
from app.core.constants import DEFAULT_ORG_ID

router = APIRouter(prefix="/users", tags=["users"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/", status_code=201)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    try:
        existing = db.query(User).filter(User.email == user.email).first()
        if existing:
            raise HTTPException(status_code=400, detail="Email already exists")

        db_user = User(
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            password_hash=hash_password(user.password),  # ✅ correct
            role=user.role,
            org_id=DEFAULT_ORG_ID
        )

        db.add(db_user)
        db.flush()  # gets ID without commit

        audit = AuditLog(
            actor_id=db_user.id,
            action="user.created",
            target=db_user.id,
            event_metadata={"email": db_user.email}
        )

        db.add(audit)
        db.commit()

        return {
            "id": db_user.id,
            "first_name": db_user.first_name,
            "last_name": db_user.last_name,
            "email": db_user.email,
            "role": db_user.role
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="User creation failed")
