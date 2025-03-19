import base64
import os

from modules.supabase_client import supabase
from modules.utils import SALT_SIZE, derive_key


def sign_up(email: str, password: str):
    """Registers a new user with Supabase Authentication and stores encryption salt."""
    try:
        response = supabase.auth.sign_up({"email": email, "password": password})

        if response.user:
            user_id = response.user.id  # Get user ID
            salt = os.urandom(SALT_SIZE)  # Generate a new random salt
            salt_encoded = base64.b64encode(salt).decode()  # Encode it for storage

            # Store the salt in a separate table `user_keys`
            supabase.table("user_keys").insert(
                {"user_id": user_id, "encryption_salt": salt_encoded}
            ).execute()

            return {
                "success": True,
                "message": "Sign-up successful! You can now log in.",
            }

        return {"success": False, "message": "Sign-up failed. Try again."}

    except Exception as e:
        return {"success": False, "message": str(e)}


def log_in(email: str, password: str):
    """Logs in an existing user and derives encryption key."""
    try:
        response = supabase.auth.sign_in_with_password(
            {"email": email, "password": password}
        )

        if response.user:
            user_id = response.user.id

            # Retrieve stored salt from `user_keys`
            salt_response = (
                supabase.table("user_keys")
                .select("encryption_salt")
                .eq("user_id", user_id)
                .execute()
            )

            if not salt_response.data:
                return {"success": False, "message": "Encryption salt not found."}

            salt = base64.b64decode(salt_response.data[0]["encryption_salt"])

            # Derive encryption key from password
            encryption_key = derive_key(password, salt)

            user_data = {
                "id": user_id,
                "email": response.user.email,
                "encryption_key": encryption_key,  # Store the derived key in memory
            }

            return {"success": True, "user": user_data}

        return {"success": False, "message": "Invalid credentials"}

    except Exception as e:
        return {"success": False, "message": str(e)}


def log_out():
    """Logs out the currently logged-in user."""
    try:
        supabase.auth.sign_out()
        return {"success": True, "message": "Logged out successfully"}
    except Exception as e:
        return {"success": False, "message": str(e)}


def get_current_user():
    """Returns the currently logged-in user or None."""
    try:
        user = supabase.auth.get_user()
        return user if user else None
    except Exception:
        return None


def is_logged_in():
    """Checks if a user is currently logged in."""
    return get_current_user() is not None


def request_password_reset(email):
    """Send an OTP for password reset via Supabase."""
    try:
        supabase.auth.reset_password_for_email(email)

        return {"success": True, "message": "OTP sent to your email."}

    except Exception as e:
        return {"success": False, "message": f"Error: {str(e)}"}


def verify_otp_and_reset_password(email, otp, new_password):
    """Verify OTP and reset password in Supabase."""
    try:
        # Verify the OTP
        response = supabase.auth.verify_otp(
            {"email": email, "token": otp, "type": "recovery"}
        )

        if response:
            # Update password after OTP is verified
            update_response = supabase.auth.update_user({"password": new_password})

            if update_response:
                return {"success": True, "message": "Password reset successful."}
            return {"success": False, "message": "Failed to update password."}

        return {"success": False, "message": "Invalid OTP."}

    except Exception as e:
        return {"success": False, "message": str(e)}
