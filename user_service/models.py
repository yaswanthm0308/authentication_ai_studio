from sqlalchemy import Column, String, Boolean, DateTime
from sqlalchemy.dialects.postgresql import UUID
from user_service.database import Base
import uuid
from datetime import datetime

class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    firstname = Column(String, nullable=False)
    lastname = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    creationtime = Column(DateTime, default=datetime.utcnow)
    lastlogintime = Column(DateTime, nullable=True)
    isactive = Column(Boolean, default=True)
    emailverified = Column(Boolean, default=False)
    timezone = Column(String, nullable=True)
    plan = Column(String, nullable=True)
