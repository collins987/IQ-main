from app.services.auth_audit import log_auth_attempt
from sqlalchemy.orm import Session

def login(..., db: Session = Depends(get_db)):
    # validate password...
    success = password_is_valid
    log_auth_attempt(user_id=user.id, action="login_attempt", db=db, success=success)
