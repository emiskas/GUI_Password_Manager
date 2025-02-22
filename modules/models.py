import os

import psycopg2
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()


class Password(Base):
    __tablename__ = "passwords"

    id = Column(Integer, primary_key=True, autoincrement=True)
    service_name = Column(String(100), nullable=False)
    username = Column(String(100), nullable=False)
    encrypted_password = Column(String(256), nullable=False)

    def set_encrypted_password(self, plain_password, cipher):
        """Encrypt and store the password (properly formatted for DB)."""
        encrypted_bytes = cipher.encrypt(plain_password.encode("utf-8"))
        self.encrypted_password = encrypted_bytes.decode("utf-8")

    def get_decrypted_password(self, cipher):
        """Decrypt and return the password."""
        encrypted_bytes = self.encrypted_password.encode("utf-8")
        decrypted_password = cipher.decrypt(encrypted_bytes).decode("utf-8")
        return decrypted_password


# Dynamically construct the path to the database file in the "gui" folder
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")
DB_ADDRESS = os.getenv("DB_ADDRESS")
DB_PORT = os.getenv("DB_PORT")

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_ADDRESS}:{DB_PORT}/{DB_NAME}"

engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Initialize the database."""
    Base.metadata.create_all(bind=engine)
