from supabase_client import supabase


class Password:
    """Handles storing and retrieving passwords from Supabase."""

    @staticmethod
    def store_password(service_name, username, encrypted_password):
        """Stores an encrypted password in Supabase."""
        data = {
            "service_name": service_name,
            "username": username,
            "encrypted_password": encrypted_password,
        }
        response = supabase.table("passwords").insert(data).execute()
        return response

    @staticmethod
    def get_passwords():
        """Retrieves all stored passwords."""
        response = supabase.table("passwords").select("*").execute()
        return response.data
