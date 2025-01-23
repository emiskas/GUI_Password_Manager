import argparse
import os

from cryptography.fernet import Fernet
from dotenv import load_dotenv

from modules.models import Password, SessionLocal
from modules.password_manager import (
    add_password,
    export_passwords,
    generate_password,
    import_passwords,
    list_passwords,
    retrieve_password,
    set_master_password,
    verify_master_password,
    generate_key
)

session = SessionLocal()


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

        print(set_master_password(args.master_password, encryption_key.encode()))
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

        print(
            add_password(
            args.service_name,
            args.username,
            args.plain_password,
            cipher,
        )
        )

    elif args.command == "export":
        print(export_passwords(args.passwords, encryption_key))

    elif args.command == "import":
        print(import_passwords(args.path, encryption_key))

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
        print(retrieve_password(args.service_name, cipher))

    elif args.command == "list":
        print(list_passwords())


if __name__ == "__main__":
    main()
