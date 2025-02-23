import os

from flask import Flask, jsonify, request
from flask_cors import CORS
from supabase import Client, create_client

# Load credentials from environment variables
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# Ensure credentials exist
if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Missing Supabase credentials! Set SUPABASE_URL and SUPABASE_KEY.")

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Create Flask app
app = Flask(__name__)
CORS(app)  # Allow CORS for frontend requests

# AUTH REQUIRED: API Key (optional but recommended)
API_KEY = os.getenv("API_KEY")  # Set this in Render's environment variables


def check_api_key(req):
    """Check if request contains a valid API key."""
    if API_KEY and req.headers.get("Authorization") != f"Bearer {API_KEY}":
        return jsonify({"error": "Unauthorized"}), 401
    return None


# Get All Passwords
@app.route("/get_passwords", methods=["GET"])
def get_passwords():
    auth_error = check_api_key(request)
    if auth_error:
        return auth_error

    try:
        response = supabase.table("passwords").select("*").execute()
        return jsonify(response.data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Add a Password
@app.route("/add_password", methods=["POST"])
def add_password():
    auth_error = check_api_key(request)
    if auth_error:
        return auth_error

    data = request.json
    if (
        not data
        or "service_name" not in data
        or "username" not in data
        or "encrypted_password" not in data
    ):
        return jsonify({"error": "Invalid data"}), 400

    try:
        response = supabase.table("passwords").insert(data).execute()
        return jsonify(response.data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Update a Password
@app.route("/update_password", methods=["PUT"])
def update_password():
    auth_error = check_api_key(request)
    if auth_error:
        return auth_error

    data = request.json
    if not data or "id" not in data:
        return jsonify({"error": "Missing password ID"}), 400

    try:
        response = (
            supabase.table("passwords").update(data).eq("id", data["id"]).execute()
        )
        return jsonify(response.data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Delete a Password
@app.route("/delete_password", methods=["DELETE"])
def delete_password():
    auth_error = check_api_key(request)
    if auth_error:
        return auth_error

    password_id = request.args.get("id")
    if not password_id:
        return jsonify({"error": "Missing password ID"}), 400

    try:
        response = supabase.table("passwords").delete().eq("id", password_id).execute()
        return jsonify({"message": "Password deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Run Flask app locally
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
