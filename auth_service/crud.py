from sqlalchemy.orm import Session
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from . import models
import logging

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def authenticate_user(db: Session, email: str, password: str):
    user = get_user_by_email(db, email)
    if user and verify_password(password, user.password):
        update_last_login_time(db, user)
        return user
    return None

def store_token(db: Session, user: models.User, token: str, ip_address: str = None, user_agent: str = None):
    """Stores a new token for the user, replacing any existing active token."""
    try:
        # Check if there's an existing active token for the user and deactivate it
        existing_token = db.query(models.Token).filter(models.Token.userid == user.id, models.Token.is_active == True).first()
        if existing_token:
            existing_token.is_active = False
            existing_token.revoked_at = datetime.now(timezone.utc)
            db.commit()
        
        # Store the new token
        token_data = models.Token(
            token_hash=token,
            userid=user.id,
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=100),
            is_active=True,
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.add(token_data)
        db.commit()
        db.refresh(token_data)
        logger.info("Token stored successfully")
        return token_data
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to store token: {e}")
        raise e

def update_token(db: Session, user: models.User, token: str, ip_address: str = None, user_agent: str = None):
    """Update an existing token or create a new one if necessary."""
    token_data = db.query(models.Token).filter(models.Token.userid == user.id, models.Token.is_active == True).first()
    if token_data:
        token_data.token_hash = token
        token_data.issued_at = datetime.now(timezone.utc)
        token_data.expires_at = datetime.now(timezone.utc) + timedelta(seconds=100)
        token_data.ip_address = ip_address
        token_data.user_agent = user_agent
        db.commit()
        db.refresh(token_data)
    else:
        store_token(db, user, token, ip_address, user_agent)

def revoke_token(db: Session, token_hash: str):
    """Revoke a token by setting its revoked_at field."""
    token_data = db.query(models.Token).filter(models.Token.token_hash == token_hash, models.Token.is_active == True).first()
    if token_data:
        token_data.revoked_at = datetime.now(timezone.utc)
        token_data.is_active = False
        db.commit()
        db.refresh(token_data)
        logger.info("Token revoked successfully")
        return token_data
    return None

def is_token_valid(db: Session, token_hash: str):
    """Check if a token is valid (i.e., not revoked and not expired)."""
    token_data = db.query(models.Token).filter(models.Token.token_hash == token_hash).first()
    if not token_data or not token_data.is_active:
        return False
    
    # Check if the token is revoked
    if token_data.revoked_at is not None:
        return False
    
    # Check if the token is expired
    if token_data.expires_at < datetime.now(timezone.utc):
        return False
    
    return True

def update_last_login_time(db: Session, user: models.User):
    """Update the last login time for a user."""
    user.lastlogintime = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
