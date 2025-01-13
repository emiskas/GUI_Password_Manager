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


def add_password(service_name, username, plain_password, cipher):
    """Add a new password entry to the database."""
    password = Password(
        service_name=service_name,
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
        print(f"Username: {password.username}")
        print(f"Password: {decrypted_password}")
    else:
        print(f"No entry found for service: {service_name}")


def list_passwords():
    """List all stored passwords."""
    passwords = session.query(Password).all()
    if passwords:
        for password in passwords:
            print(f"Service: {password.service_name}, Username: {password.username}")
    else:
        print("No passwords stored yet.")


def set_master_password(input_password, encryption_key):
    encrypted_master_password = encrypt_master_password(input_password, encryption_key)
    with open(".env", "a") as f:
        f.write(f"ENCRYPTED_MASTER_PASSWORD={encrypted_master_password.decode()}\n")

    print("Master password set successfully!")


def generate_password(length=16):
    import random
    import string

    characters = string.ascii_letters + string.digits + string.punctuation

    return "".join(random.choice(characters) for i in range(0, length))


def export_passwords(passwords: list = None):
    import datetime
    import os

    try:
        # Fetch passwords if not provided
        if not passwords:
            try:
                passwords = session.query(Password).all()
            except Exception as e:
                print(f"Error retrieving passwords from database: {str(e)}")
                return

        # Ensure the backup directory exists
        backup_dir = os.path.join(os.getcwd(), "backup")
        if not os.path.exists(backup_dir):
            try:
                os.makedirs(backup_dir)
                print(f"Backup directory created at {backup_dir}")
            except OSError as e:
                print(f"Error creating backup directory: {e}")
                return

        today = datetime.datetime.now().strftime("%Y-%m-%d")
        path = os.path.join(backup_dir, f"{today}.txt")

        try:
            with open(path, "w") as f:
                for password in passwords:
                    # Ensure we handle any unexpected issues with writing data
                    try:
                        f.write(
                            f"Service: {password.service_name}, Username: {password.username}, Password: {password.encrypted_password}\n"
                        )
                    except Exception as write_error:
                        print(
                            f"Error writing password entry for service '{password.service_name}': {str(write_error)}"
                        )
                        continue  # Skip this password entry if an error occurs

            print(f"Passwords exported successfully to {path}!")

        except IOError as e:
            print(f"Error writing to file {path}: {e}")

    except Exception as e:
        print(f"Unexpected error occurred during export: {str(e)}")


def import_passwords(path, encryption_key):
    if not path:
        print("You must provide a path to the file.")
        return

    try:
        # Attempt to open the file
        with open(path, "r") as f:
            for line in f.readlines():
                try:
                    # Attempt to parse the line
                    parts = line.strip().split(", ")
                    if len(parts) != 3:
                        print(f"Skipping invalid line: {line.strip()}")
                        continue

                    service = parts[0].split(": ")[1]
                    username = parts[1].split(": ")[1]
                    encrypted_password = parts[2].split(": ")[1]

                    # Clean the password if it's in 'b' format
                    if encrypted_password.startswith(
                        "b'"
                    ) and encrypted_password.endswith("'"):
                        encrypted_password = encrypted_password[2:-1]

                    # Check if this entry already exists in the database
                    if (
                        session.query(Password)
                        .filter(Password.service_name == service)
                        .first()
                        and session.query(Password)
                        .filter(Password.username == username)
                        .first()
                    ):
                        continue

                    try:
                        # Attempt to decrypt the password
                        encrypted_password_bytes = encrypted_password.encode("utf-8")
                        cipher = Fernet(encryption_key)
                        decrypted_password = cipher.decrypt(
                            encrypted_password_bytes
                        ).decode("utf-8")

                        # Add the password to the database
                        add_password(service, username, decrypted_password, cipher)
                        print(f"Imported password for {service}")

                    except Exception as e:
                        print(f"Error decrypting password for {service}: {str(e)}")

                except Exception as line_error:
                    print(f"Error processing line: {line.strip()} - {line_error}")

        try:
            # Commit changes after processing the file
            session.commit()

        except Exception as commit_error:
            print(f"Error committing changes: {commit_error}")
            session.rollback()

    except FileNotFoundError:
        print(f"Error: The file at {path} was not found.")
    except IOError as e:
        print(f"Error opening or reading the file {path}: {e}")
    except Exception as e:
        print(f"Unexpected error occurred during import: {str(e)}")


# CLI setup
def main():
    parser = argparse.ArgumentParser(description="Password Manager CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Add command
    add_parser = subparsers.add_parser("add", help="Add a new password")
    add_parser.add_argument("service_name", help="Name of the service")
    add_parser.add_argument("username", help="Username for the service")
    add_parser.add_argument(
        "plain_password", nargs="?", help="Password for the service"
    )
    add_parser.add_argument(
        "--generate", action="store_true", help="Generate a random password"
    )

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

    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete a saved password")
    delete_parser.add_argument("service_name", help="Name of the service to delete")

    # Update command
    update_parser = subparsers.add_parser("update", help="Update a saved password")
    update_parser.add_argument("service_name", help="Name of the service to update")
    update_parser.add_argument(
        "new_password", nargs="?", help="New password for the service"
    )
    update_parser.add_argument(
        "--generate", action="store_true", help="Generate a random password"
    )

    # Generate command
    generate_parser = subparsers.add_parser(
        "generate", help="Generate a random password"
    )
    generate_parser.add_argument(
        "--length", type=int, default=16, help="Length of the generated password"
    )

    # Export command
    export_parser = subparsers.add_parser("export", help="Export passwords")
    export_parser.add_argument("--passwords", nargs="*", help="Service names to export")

    # Import command
    import_parser = subparsers.add_parser("import", help="Import passwords")
    import_parser.add_argument("path", help="Path to the file to import")

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
        if os.getenv("ENCRYPTED_MASTER_PASSWORD"):
            print("Master password already set.")
            return

        set_master_password(args.master_password, encryption_key.encode())
        return

    elif args.command == "generate":
        generated_password = generate_password(args.length)
        print(f"Generated password: {generated_password}")
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
        if args.generate:
            args.plain_password = generate_password()
        elif not args.plain_password:
            print(
                "Error: You must provide a password or use '--generate' to create one."
            )
            return

        add_password(
            args.service_name,
            args.username,
            args.plain_password,
            cipher,
        )

    elif args.command == "export":
        export_passwords(args.passwords)
        print("Passwords exported successfully!")

    elif args.command == "import":
        import_passwords(args.path, encryption_key)
        print("Passwords imported successfully!")

    elif args.command == "delete":
        password = (
            session.query(Password)
            .filter(Password.service_name == args.service_name)
            .first()
        )
        if password:
            session.delete(password)
            session.commit()
            print(f"Password for {args.service_name} deleted successfully!")
        else:
            print(f"No entry found for service: {args.service_name}")

    elif args.command == "update":
        password = (
            session.query(Password)
            .filter(Password.service_name == args.service_name)
            .first()
        )
        if args.generate:
            args.new_password = generate_password()
        if password:
            cipher = Fernet(encryption_key)
            password.encrypted_password = cipher.encrypt(args.new_password.encode())
            session.commit()
            print(f"Password for {args.service_name} updated successfully!")
        else:
            print(f"No entry found for service: {args.service}")

    elif args.command == "retrieve":
        cipher = Fernet(encryption_key)
        retrieve_password(args.service_name, cipher)

    elif args.command == "list":
        list_passwords()


if __name__ == "__main__":
    main()
