from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, UUID
from sqlalchemy.orm import relationship
from auth_service.database import Base
from datetime import datetime
import uuid

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    creationtime = Column(DateTime, default=datetime.utcnow)
    lastlogintime = Column(DateTime, default=datetime.utcnow)
    isactive = Column(Boolean, default=True)

class Token(Base):
    __tablename__ = "tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token_hash = Column(String(255), unique=True, nullable=False)
    userid = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    issued_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)
    revoked_at = Column(DateTime)
    ip_address = Column(String(45))
    user_agent = Column(String)
