import base64
import datetime
import os
import sys
from pathlib import Path

from Crypto.Cipher import AES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from modules.supabase_client import supabase

# Constants
SALT_SIZE = 16
KEY_SIZE = 32  # AES-256
ITERATIONS = 100000


def is_duplicate_entry(service_name, username, user_id):
    """Check if service/username pair exists for user in Supabase."""
    response = (
        supabase.table("passwords")
        .select("id")
        .eq("user_id", user_id)
        .eq("service_name", service_name)
        .eq("username", username)
        .execute()
    )
    return bool(response.data)


def derive_key(user_password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from the user's login password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(user_password.encode())


def encrypt_password(plain_password, user_key):
    """Encrypt the password using AES-256."""
    salt = os.urandom(SALT_SIZE)
    key = derive_key(user_key, salt)

    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plain_password.encode())

    # Store salt, nonce, tag, and ciphertext, then base64 encode it
    encrypted_data = base64.b64encode(
        salt + cipher.nonce + tag + ciphertext
    ).decode()

    return {"success": True, "encrypted_password": encrypted_data}


def decrypt_password(encrypted_password, user_key):
    """Decrypt the AES-encrypted password."""
    try:
        encrypted_data = base64.b64decode(encrypted_password)

        salt = encrypted_data[:SALT_SIZE]
        nonce = encrypted_data[SALT_SIZE : SALT_SIZE + 16]
        tag = encrypted_data[SALT_SIZE + 16 : SALT_SIZE + 32]
        ciphertext = encrypted_data[SALT_SIZE + 32 :]

        key = derive_key(user_key, salt)

        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)

        return {
            "success": True,
            "decrypted_password": decrypted_password.decode()
        }

    except ValueError:
        return {
            "success": False,
            "message": "Decryption failed: Invalid key or data."
        }

    except Exception as e:
        return {
            "success": False,
            "message": f"Unexpected error during decryption: {str(e)}",
        }


def get_user_id():
    """Retrieve the user ID of the currently logged-in user."""
    try:
        user_response = supabase.auth.get_user()
        user = getattr(user_response, "user", None)

        if not user or not getattr(user, "id", None):
            return {"success": False, "message": "User ID not found."}

        return {"success": True, "user_id": user.id}

    except Exception as e:
        return {
            "success": False,
            "message": f"Error retrieving user: {str(e)}"
        }


def add_password(service_name, username, plain_password):
    """Add a new password entry to Supabase."""
    user_id_response = get_user_id()

    if not user_id_response["success"]:
        # Return error if user ID retrieval failed
        return user_id_response

    user_id = user_id_response["user_id"]

    # Fetch user's encryption key
    response = (
        supabase.table("user_keys")
        .select("encryption_salt")
        .eq("user_id", user_id)
        .single()
        .execute()
    )

    if not response.data:
        return {
            "success": False,
            "message": "Error: Encryption key not found for this user.",
        }

    user_key = response.data["encryption_salt"]

    # Encrypt the password
    encrypted_password = encrypt_password(plain_password, user_key)

    if not is_duplicate_entry(service_name, username, user_id):
        try:
            insert_response = (
                supabase.table("passwords")
                .insert(
                    {
                        "user_id": user_id,
                        "service_name": service_name,
                        "username": username,
                        "encrypted_password": encrypted_password[
                            "encrypted_password"
                        ],
                    }
                )
                .execute()
            )

            if "data" in insert_response:
                return {
                    "success": True,
                    "message": "Password added successfully"
                }
            else:
                return {"success": False, "message": "Failed to add password"}

        except Exception as e:
            return {"success": False, "message": f"Database error: {str(e)}"}

    else:
        return {
            "success": False,
            "message": f"Username {username} "
                       f"for the service {service_name} already exists.",
        }


def retrieve_password(service_name):
    """Retrieve and decrypt a password from Supabase."""
    user_id_response = get_user_id()

    if not user_id_response["success"]:
        # Return error if user ID retrieval failed
        return user_id_response

    user_id = user_id_response["user_id"]

    key_response = (
        supabase.table("user_keys")
        .select("encryption_salt")
        .eq("user_id", user_id)
        .single()
        .execute()
    )

    if not key_response.get("data"):
        return {
            "success": False,
            "message": "Error: Encryption key not found."
        }

    user_key = key_response["data"].get("encryption_salt")

    response = (
        supabase.table("passwords")
        .select("service_name, username, encrypted_password")
        .eq("user_id", user_id)
        .eq("service_name", service_name)
        .execute()
    )

    if not response.get("data"):
        return {
            "success": False,
            "message": f"No entry found for service: {service_name}",
        }

    entry = response["data"][0]

    decrypted_password = decrypt_password(
        entry["encrypted_password"],
        user_key
    )

    if not decrypted_password["success"]:
        # Return the decryption error
        return decrypted_password

    return {
        "success": True,
        "service": entry["service_name"],
        "username": entry["username"],
        "password": decrypted_password["decrypted_password"],
    }


def list_passwords():
    """Fetch all stored passwords for the logged-in user."""
    user_id_response = get_user_id()

    if not user_id_response["success"]:
        # Return error if user ID retrieval failed
        return user_id_response

    user_id = user_id_response["user_id"]

    response = (
        supabase.table("passwords")
        .select("service_name, username")
        .eq("user_id", user_id)
        .execute()
    )

    if response.data:
        return {"success": True, "data": response.data}
    else:
        return {"success": False, "message": "No passwords found."}


def generate_password(length=16):
    """Generate a random password."""
    import random
    import string

    characters = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(characters) for i in range(0, length))


def is_base64(string):
    """Checks if a string is valid Base64."""
    try:
        base64.b64decode(string, validate=True)
        return True
    except Exception:
        return False


def get_base_path():
    if getattr(sys, "frozen", False):
        # The app is bundled (e.g., by PyInstaller)
        return os.path.dirname(sys.executable)

    else:
        # The app is not bundled, run normally
        return os.path.dirname(os.path.abspath(__file__))

# Example: Create a folder next to the executable or script
new_folder_path = os.path.join(get_base_path(), "backup")
os.makedirs(new_folder_path, exist_ok=True)


def export_passwords(decrypt=None):
    """Export passwords from Supabase to a local file."""
    user_id_response = get_user_id()

    if not user_id_response["success"]:
        # Return error if user ID retrieval failed
        return user_id_response

    user_id = user_id_response["user_id"]

    response = (
        supabase.table("passwords")
        .select("service_name, username, encrypted_password")
        .eq("user_id", user_id)
        .execute()
    )

    if not response.data:
        return {
            "success": False,
            "message": "No passwords found in Supabase."
        }

    backup_dir = os.path.join(get_base_path(), "backup")
    os.makedirs(backup_dir, exist_ok=True)

    today = datetime.datetime.now().strftime("%Y-%m-%d")
    path = os.path.join(backup_dir, f"{today}.txt")

    if decrypt:
        # Fetch user's encryption key
        key_response = (
            supabase.table("user_keys")
            .select("encryption_salt")
            .eq("user_id", user_id)
            .single()
            .execute()
        )
        user_key = key_response.data["encryption_salt"]

        try:
            with open(path, "w") as f:
                for entry in response.data:
                    decrypted_password = decrypt_password(
                        entry["encrypted_password"], user_key
                    )

                    if not decrypted_password["success"]:
                        f.write(
                            f"Error decrypting password for "
                            f"{entry['service_name']}: "
                            f"{decrypted_password['message']}\n"
                        )
                    else:
                        f.write(
                            f"Service: {entry['service_name']}, "
                            f"Username: {entry['username']}, "
                            f"Password: "
                            f"{decrypted_password['decrypted_password']}\n"
                        )

            return {
                "success": True,
                "message": f"Passwords exported successfully to {path}",
            }

        except Exception as e:
            return {
                "success": False,
                "message": f"Error exporting passwords: {str(e)}"
            }

    try:
        with open(path, "w") as f:
            for entry in response.data:
                f.write(
                    f"Service: {entry['service_name']}, "
                    f"Username: {entry['username']}, "
                    f"Password: {entry['encrypted_password']}\n"
                )

        return {
            "success": True,
            "message": f"Passwords exported successfully to {path}",
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Error exporting passwords: {str(e)}"
        }


def import_passwords(path):
    """Import passwords from a local file to Supabase."""
    if not os.path.exists(path):
        return {"success": False, "message": "Error: File not found."}

    user_id_response = get_user_id()

    if not user_id_response["success"]:
        return user_id_response

    user_id = user_id_response["user_id"]

    try:
        with open(path, "r") as f:
            lines = f.readlines()
            for line in lines:
                parts = line.strip().split(", ")
                if len(parts) != 3:
                    return {
                        "success": False,
                        "message": f"Skipping invalid line: {line.strip()}",
                    }

                service = parts[0].split(": ")[1]
                username = parts[1].split(": ")[1]
                password = parts[2].split(": ")[1]

                if is_base64(password):
                    # Fetch user's encryption salt
                    key_response = (
                        supabase.table("user_keys")
                        .select("encryption_salt")
                        .eq("user_id", user_id)
                        .single()
                        .execute()
                    )
                    user_key = key_response.data["encryption_salt"]
                    password = decrypt_password(password, user_key)[
                        "decrypted_password"
                    ]

                if not is_duplicate_entry(service, username, user_id):
                    add_password(service, username, password)

        return {
            "success": True,
            "message": f"Successfully imported stored credentials from: "
                       f"{path}",
        }

    except Exception as e:
        return {
            "success": False,
            "message": f"Error importing passwords: {str(e)}"
        }
