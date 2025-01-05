import argparse

from models import Password, SessionLocal, init_db

init_db()

session = SessionLocal()


def add_password(service_name, service_url, username, plain_password):
    """Add a new password entry to the database."""
    password = Password(
        service_name=service_name,
        service_url=service_url,  # Accepts None if not provided
        username=username,
    )
    password.set_encrypted_password(plain_password)
    session.add(password)
    session.commit()
    print(f"Password for {service_name} added successfully!")


def retrieve_password(service_name):
    """Retrieve a password entry by service name."""
    password = (
        session.query(Password).filter(Password.service_name == service_name).first()
    )
    if password:
        print(f"Service: {password.service_name}")
        print(f"URL: {password.service_url}")
        print(f"Username: {password.username}")
        print(f"Encrypted Password: {password.encrypted_password}")
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

    # Parse arguments
    args = parser.parse_args()

    # Handle commands
    if args.command == "add":
        add_password(
            args.service_name, args.service_url, args.username, args.plain_password
        )
    elif args.command == "retrieve":
        retrieve_password(args.service_name)
    elif args.command == "list":
        list_passwords()


if __name__ == "__main__":
    main()
