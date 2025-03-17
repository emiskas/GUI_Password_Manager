import datetime
import os
from pathlib import Path

from modules.supabase_client import supabase

# TODO: Use the same convention when returning or printing function outputs


def get_env_path():
    """
    Resolve the path to the .env file.

    Returns:
        Path: Path object pointing to the .env file.
    """
    return Path(__file__).parent.parent / ".env"


def get_user_id():
    """Retrieve the user ID of the currently logged-in user."""
    try:
        user_response = supabase.auth.get_user()
        if user_response and hasattr(user_response, "user"):
            user = user_response.user
            if user and hasattr(user, "id"):
                return user.id

        print("Error: User ID not found.")
        return None
    except Exception as e:
        print(f"Error retrieving user: {e}")
        return None


def add_password(service_name, username, plain_password):
    """Add a new password entry to Supabase."""
    user_id = get_user_id()

    if not user_id:
        return "Error: No authenticated user found."

    response = (
        supabase.table("passwords")
        .insert(
            {
                "user_id": user_id,
                "service_name": service_name,
                "username": username,
                "encrypted_password": plain_password,
            }
        )
        .execute()
    )
    return "Password added successfully" if response else "Failed to add password"


def retrieve_password(service_name):
    """Retrieve a password entry by service name from Supabase."""
    user_id = get_user_id()

    if not user_id:
        return "Error: No authenticated user found."

    response = (
        supabase.table("passwords")
        .select("service_name, username, password")
        .eq("user_id", user_id)
        .eq("service_name", service_name)
        .execute()
    )

    if response.data:
        entry = response.data[0]
        return (
            f"Service: {entry['service_name']}\n"
            f"Username: {entry['username']}\n"
            f"Password: {entry['password']}"
        )
    else:
        return f"No entry found for service: {service_name}"


def list_passwords():
    """List all stored passwords from Supabase for the logged-in user."""
    user_id = get_user_id()

    if not user_id:
        return "Error: No authenticated user found."

    response = (
        supabase.table("passwords")
        .select("service_name, username")
        .eq("user_id", user_id)
        .execute()
    )

    if response.data:
        return response.data
    else:
        return []


def generate_password(length=16):
    import random
    import string

    characters = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(characters) for i in range(0, length))


def export_passwords():
    """Export passwords from Supabase to a local file."""
    response = (
        supabase.table("passwords")
        .select("service_name, username, encrypted_password")
        .execute()
    )

    if not response.data:
        return "No passwords found in Supabase."

    backup_dir = os.path.join(os.getcwd(), "backup")
    os.makedirs(backup_dir, exist_ok=True)

    today = datetime.datetime.now().strftime("%Y-%m-%d")
    path = os.path.join(backup_dir, f"{today}.txt")
    try:
        with open(path, "w") as f:
            for entry in response.data:
                f.write(
                    f"Service: {entry["service_name"]}, Username: {entry["username"]}, Password: {entry["encrypted_password"]}\n"
                )
        return f"Passwords exported successfully to {path}"
    except Exception as e:
        return f"Error exporting passwords: {str(e)}"


def import_passwords(path):
    """Import passwords from a local file to Supabase."""
    if not os.path.exists(path):
        return "Error: File not found."

    try:
        with open(path, "r") as f:
            lines = f.readlines()
            for line in lines:
                parts = line.strip().split(", ")
                if len(parts) != 3:
                    print(f"Skipping invalid line: {line.strip()}")
                    continue

                service = parts[0].split(": ")[1]
                username = parts[1].split(": ")[1]
                password = parts[2].split(": ")[1]

                # Insert into Supabase
                add_password(service, username, password)
        return f"Successfully imported accounts from: {path}"
    except Exception as e:
        return f"Error importing passwords: {str(e)}"
