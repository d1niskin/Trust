from sqlalchemy import Column, Integer, String, Text, DateTime, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

DATABASE_URL = "sqlite:///./unitrust.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class Ticket(Base):
    __tablename__ = "tickets"
    id = Column(Integer, primary_key=True, index=True)
    ticket_number = Column(String, unique=True, index=True)
    hashed_pin = Column(String)
    category = Column(String, index=True)
    encrypted_description = Column(Text)
    file_url = Column(String, nullable=True) # <-- ССЫЛКА НА ФАЙЛ В ЖАЛОБЕ
    status = Column(String, default="Новое")
    created_at = Column(DateTime, default=datetime.utcnow)

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    ticket_number = Column(String, index=True)
    sender = Column(String)
    encrypted_text = Column(Text)
    file_url = Column(String, nullable=True) # <-- ССЫЛКА НА ФАЙЛ В ЧАТЕ
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)