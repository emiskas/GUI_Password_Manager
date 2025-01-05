from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from bcrypt import hashpw, gensalt, checkpw

Base = declarative_base()


class Password(Base):
    __tablename__ = "passwords"

    id = Column(Integer, primary_key=True, autoincrement=True)
    service_name = Column(String(100), nullable=False)
    service_url = Column(String(200), nullable=True)
    username = Column(String(100), nullable=False)
    encrypted_password = Column(String(128), nullable=False)

    def set_encrypted_password(self, plain_password):
        """Hash and store the password."""
        self.encrypted_password = hashpw(
            plain_password.encode("utf-8"), gensalt()
        ).decode("utf-8")

    def check_encrypted_password(self, plain_password):
        """Check the password against the stored hash."""
        return checkpw(
            plain_password.encode("utf-8"), self.encrypted_password.encode("utf-8")
        )


DATABASE_URL = "sqlite:///passwords.sqlite"

engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(bind=engine)

# Run this file to create the database
if __name__ == "__main__":
    Base.metadata.create_all(bind=engine)
