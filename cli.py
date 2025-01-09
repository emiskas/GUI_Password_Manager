import argparse
import os

from cryptography.fernet import Fernet
from dotenv import load_dotenv

from models import Password, SessionLocal, init_db

init_db()
session = SessionLocal()


def generate_key():
    key = Fernet.generate_key()
    return key


def encrypt_master_password(master_password, key):
    cipher = Fernet(key)
    encrypted_password = cipher.encrypt(master_password.encode())
    return encrypted_password


def verify_master_password(input_password, encrypted_password, key):
    cipher = Fernet(key)

    try:
        decrypted_password = cipher.decrypt(encrypted_password).decode()
        return decrypted_password == input_password

    except Exception as e:
        return False


def add_password(service_name, service_url, username, plain_password, cipher):
    """Add a new password entry to the database."""
    password = Password(
        service_name=service_name,
        service_url=service_url,
        username=username,
    )
    password.set_encrypted_password(plain_password, cipher)
    session.add(password)
    session.commit()
    print(f"Password for {service_name} added successfully!")


def retrieve_password(service_name, cipher):
    """Retrieve a password entry by service name."""
    password = (
        session.query(Password).filter(Password.service_name == service_name).first()
    )
    if password:
        decrypted_password = password.get_decrypted_password(cipher)

        print(f"Service: {password.service_name}")
        print(f"URL: {password.service_url}")
        print(f"Username: {password.username}")
        print(f"Password: {decrypted_password}")
    else:
        print(f"No entry found for service: {service_name}")


def list_passwords():
    """List all stored passwords."""
    passwords = session.query(Password).all()
    if passwords:
        for password in passwords:
            print(
                f"Service: {password.service_name}, Username: {password.username}, URL: {password.service_url}"
            )
    else:
        print("No passwords stored yet.")


def set_master_password(input_password, encryption_key):
    encrypted_master_password = encrypt_master_password(input_password, encryption_key)
    with open(".env", "a") as f:
        f.write(f"ENCRYPTED_MASTER_PASSWORD={encrypted_master_password.decode()}\n")

    print("Master password set successfully!")


# CLI setup
def main():
    parser = argparse.ArgumentParser(description="Password Manager CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Add command
    add_parser = subparsers.add_parser("add", help="Add a new password")
    add_parser.add_argument("service_name", help="Name of the service")
    add_parser.add_argument("username", help="Username for the service")
    add_parser.add_argument("plain_password", help="Password for the service")
    add_parser.add_argument("--service_url", help="URL of the service", default=None)

    # Retrieve command
    retrieve_parser = subparsers.add_parser("retrieve", help="Retrieve a password")
    retrieve_parser.add_argument("service_name", help="Name of the service to retrieve")

    # List command
    list_parser = subparsers.add_parser("list", help="List all stored passwords")

    # Setpass command
    setpass_parser = subparsers.add_parser("setpass", help="Set the master password")
    setpass_parser.add_argument(
        "master_password", help="Master password for the password manager"
    )

    # Parse arguments
    args = parser.parse_args()

    load_dotenv()
    encryption_key = os.getenv("ENCRYPTION_KEY")

    if not encryption_key:
        encryption_key = generate_key().decode()

        with open(".env", "a") as f:
            f.write(f"ENCRYPTION_KEY={encryption_key}\n")

        print("ENCRYPTION_KEY generated and saved.")

    if args.command == "setpass":
        set_master_password(args.master_password, encryption_key.encode())
        return

    input_password = input("Enter your master password: ")
    stored_encrypted_password = os.getenv("ENCRYPTED_MASTER_PASSWORD")
    if stored_encrypted_password:
        # Decrypt the stored password and verify
        if verify_master_password(
            input_password, stored_encrypted_password.encode(), encryption_key.encode()
        ):
            print("Master password verified successfully!")
        else:
            print("Incorrect master password.")
            return

    if args.command == "add":
        cipher = Fernet(encryption_key)
        add_password(
            args.service_name,
            args.service_url,
            args.username,
            args.plain_password,
            cipher,
        )

    elif args.command == "retrieve":
        cipher = Fernet(encryption_key)
        retrieve_password(args.service_name, cipher)

    elif args.command == "list":
        list_passwords()


if __name__ == "__main__":
    main()
