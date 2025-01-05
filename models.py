from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()


class Password(Base):
    __tablename__ = "passwords"

    id = Column(Integer, primary_key=True, autoincrement=True)
    service_name = Column(String(100), nullable=False)
    service_url = Column(String(200), nullable=True)
    username = Column(String(100), nullable=False)
    encrypted_password = Column(String(256), nullable=False)

    def set_encrypted_password(self, plain_password, cipher):
        """Encrypt and store the password."""
        self.encrypted_password = cipher.encrypt(plain_password.encode("utf-8"))

    def get_decrypted_password(self, cipher):
        """Decrypt and return the password."""
        return cipher.decrypt(self.encrypted_password).decode("utf-8")


DATABASE_URL = "sqlite:///passwords.sqlite"

engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(bind=engine)


def init_db():
    """Initialize the database."""
    Base.metadata.create_all(bind=engine)
