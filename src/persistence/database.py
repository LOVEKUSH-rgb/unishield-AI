"""
UniShield AI -- Database Module
===============================
Provides SQLAlchemy engine, session maker, and Base model.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from src.utils.logging import get_logger
from src.utils.config import settings

logger = get_logger(__name__)

DATABASE_URL = settings.database_url
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine_error = None
try:
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
        pool_pre_ping=True
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base = declarative_base()
except Exception as e:
    import traceback
    logger.error(f"Failed to initialize database engine: {e}")
    engine_error = traceback.format_exc()
    engine = None
    SessionLocal = None

def get_db():
    if not SessionLocal:
        yield None
        return
        
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    if not engine or not SessionLocal:
        return
    import src.persistence.models 
    from src.persistence.models import User
    
    # We no longer use Base.metadata.create_all() here.
    # Schema creation is fully managed by Alembic in deployment.
    
    db = SessionLocal()
    try:
        from src.api.auth import get_password_hash
        # Seed default users
        for role, username in [("admin", "admin"), ("analyst", "analyst"), ("viewer", "viewer")]:
            if not db.query(User).filter(User.username == username).first():
                user = User(username=username, password_hash=get_password_hash("changeme"), role=role)
                db.add(user)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to seed users: {e}")
        db.rollback()
    finally:
        db.close()
