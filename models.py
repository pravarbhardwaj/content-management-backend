from sqlalchemy import Column, Integer, String, Boolean
from db import Base


class User(Base):
    __tablename__ = "user"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(100), nullable=True, unique=True)
    password = Column(String(255), nullable=False)
    admin = Column(Boolean)
    
    