import datetime
import os
from pathlib import Path

from cryptography.fernet import Fernet
from dotenv import load_dotenv

from .models import Password, SessionLocal, init_db

# TODO: Use the same convention when returning or printing function outputs

init_db()
session = SessionLocal()


def get_env_path():
    """
    Resolve the path to the .env file.

    Returns:
        Path: Path object pointing to the .env file.
    """
    return Path(__file__).parent.parent / ".env"


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


def add_password(service_name, username, plain_password, cipher):
    """Add a new password entry to the database."""
    password = Password(
        service_name=service_name,
        username=username,
    )
    password.set_encrypted_password(plain_password, cipher)
    session.add(password)
    session.commit()
    return f"Password for {service_name} added successfully"


def retrieve_password(service_name, cipher):
    """Retrieve a password entry by service name."""
    password = (
        session.query(Password).filter(Password.service_name == service_name).first()
    )
    if password:
        decrypted_password = password.get_decrypted_password(cipher)

        return (
            f"Service: {password.service_name}\n"
            f"Username: {password.username}]=\n"
            f"Password: {decrypted_password}"
        )
    else:
        return f"No entry found for service: {service_name}"


def list_passwords():
    """List all stored passwords."""
    password_list = []

    passwords = session.query(Password).all()
    if passwords:
        for password in passwords:
            password_list.append(
                f"Service: {password.service_name}, Username: {password.username}"
            )
    else:
        return "No passwords stored yet."

    return password_list


def set_master_password(input_password, encryption_key):
    """
    Create a master password.
    """

    encrypted_master_password = encrypt_master_password(input_password, encryption_key)

    env_path = os.path.join(os.getcwd(), ".env")

    with open(env_path, "a") as f:
        f.write(f"ENCRYPTED_MASTER_PASSWORD={encrypted_master_password.decode()}\n")

    # Reload environment variables
    load_dotenv(override=True)

    # Fetch the latest stored password
    stored_password = os.getenv("ENCRYPTED_MASTER_PASSWORD")

    return "Master password set successfully!"


def generate_password(length=16):
    import random
    import string

    characters = string.ascii_letters + string.digits + string.punctuation

    return "".join(random.choice(characters) for i in range(0, length))


def export_passwords(encryption_key, passwords: list = None):
    try:
        if not passwords:
            try:
                passwords = session.query(Password).all()
            except Exception as e:
                return f"Error retrieving passwords from database: {str(e)}"

        backup_dir = os.path.join(os.getcwd(), "backup")
        if not os.path.exists(backup_dir):
            try:
                os.makedirs(backup_dir)
                return f"Backup directory created at {backup_dir}"
            except OSError as e:
                return f"Error creating backup directory: {e}"

        today = datetime.datetime.now().strftime("%Y-%m-%d")
        path = os.path.join(backup_dir, f"{today}.txt")

        with open(path, "w") as f:
            for password in passwords:
                try:
                    content = (
                        f"Service: {password.service_name}, "
                        f"Username: {password.username}, "
                        f"Password: {password.encrypted_password.decode()}\n"
                    )
                    f.write(content)
                except Exception as write_error:
                    print(
                        f"Error writing password entry for service '{password.service_name}': {str(write_error)}"
                    )
                    continue

        print(f"Passwords exported successfully to {path}")

        cipher = Fernet(encryption_key)
        try:
            with open(path, "rb") as f:
                file_data = f.read()

            encrypted_data = cipher.encrypt(file_data)

            with open(path, "wb") as f:
                f.write(encrypted_data)

            return f"File encrypted successfully!"

        except Exception as e:
            return f"Error during file encryption: {str(e)}"

    except Exception as e:
        return f"Unexpected error occurred during export: {str(e)}"


def import_passwords(path, encryption_key):
    if not path:
        return "You must provide a path to the file."

    try:
        with open(path, "rb") as f:
            encrypted_content = f.read()

        cipher = Fernet(encryption_key)
        try:
            decrypted_content = cipher.decrypt(encrypted_content).decode("utf-8")

            for line in decrypted_content.splitlines():
                parts = line.strip().split(", ")
                if len(parts) != 3:
                    print(f"Skipping invalid line: {line.strip()}")
                    continue

                service = parts[0].split(": ")[1]
                username = parts[1].split(": ")[1]
                encrypted_password = parts[2].split(": ")[1]

                if encrypted_password.startswith("b'") and encrypted_password.endswith(
                    "'"
                ):
                    encrypted_password = encrypted_password[2:-1]

                if (
                    session.query(Password)
                    .filter(Password.service_name == service)
                    .first()
                    and session.query(Password)
                    .filter(Password.username == username)
                    .first()
                ):
                    print(
                        f"Service '{service}' with the username '{username}' already exists. Skipping.."
                    )
                    continue
                try:
                    encrypted_password_bytes = encrypted_password.encode("utf-8")
                    decrypted_password = cipher.decrypt(
                        encrypted_password_bytes
                    ).decode("utf-8")

                    add_password(service, username, decrypted_password, cipher)
                    print(f"Imported password for {service}")

                except Exception as e:
                    return f"Error decrypting password for {service}: {str(e)}"

        except Exception as e:
            return f"Error decrypting file content: {str(e)}"

    except FileNotFoundError:
        return f"Error: The file at {path} was not found."
    except IOError as e:
        return f"Error opening or reading the file {path}: {e}"
    except Exception as e:
        return f"Unexpected error occurred during import: {str(e)}"

    return f"Successfully imported accounts from: {path}"
