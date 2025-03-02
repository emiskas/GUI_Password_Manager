from modules.supabase_client import supabase


def sign_up(email: str, password: str):
    """Registers a new user with Supabase Authentication."""
    try:
        response = supabase.auth.sign_up({"email": email, "password": password})
        if response.user:
            return {
                "success": True,
                "message": "Sign-up successful! Please check your email for verification.",
            }
        return {"success": False, "message": "Sign-up failed. Try again."}
    except Exception as e:
        return {"success": False, "message": str(e)}


def log_in(email: str, password: str):
    """Logs in an existing user."""
    try:
        response = supabase.auth.sign_in_with_password(
            {"email": email, "password": password}
        )

        if response.user:
            user_data = {
                "id": response.user.id,
                "email": response.user.email,
                "role": response.user.role if hasattr(response.user, "role") else None
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
