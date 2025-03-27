import base64
import os
import uuid
from unittest.mock import MagicMock, patch

import pytest

from modules.auth import (get_current_user, is_logged_in, log_in, log_out,
                          request_password_reset, sign_up)
from modules.utils import SALT_SIZE


@pytest.mark.parametrize(
    "email, password, expected_success",
    [
        ("test@example.com", "SecurePassword1", True),
    ],
)
def test_log_in_success(email, password, expected_success):
    # Arrange: Mock Supabase authentication and user key retrieval
    mock_sign_in = MagicMock()
    mock_sign_in.return_value = MagicMock(
        user=MagicMock(id=str(uuid.uuid4()), email=email)
    )

    # Mock the response from the user_keys table for the salt
    mock_salt_response = MagicMock()
    mock_salt_response.data = [
        {"encryption_salt": base64.b64encode(os.urandom(SALT_SIZE)).decode()}
    ]

    with patch(
        "modules.supabase_client.supabase.auth.sign_in_with_password", mock_sign_in
    ):
        with patch("modules.supabase_client.supabase.table") as mock_table:
            mock_table.return_value.select.return_value.eq.return_value.execute.return_value = (
                mock_salt_response
            )

            # Act: Call the log_in function
            result = log_in(email, password)

            # Assert: Check if the login is successful
            assert result["success"] == expected_success


@pytest.mark.parametrize(
    "email, password, expected_success",
    [
        ("test@example.com", "SecurePassword1", True),
    ],
)
def test_sign_up_success(email, password, expected_success):
    # Arrange: Mock Supabase sign-up and salt insertion
    mock_sign_up = MagicMock()
    mock_sign_up.return_value = MagicMock(
        user=MagicMock(id=str(uuid.uuid4()), email=email)
    )

    # Mock the response from the user_keys table for salt insertion
    mock_salt_response = MagicMock()
    mock_salt_response.data = []

    with patch("modules.supabase_client.supabase.auth.sign_up", mock_sign_up):
        with patch("modules.supabase_client.supabase.table") as mock_table:
            mock_table.return_value.insert.return_value.execute.return_value = (
                mock_salt_response
            )

            # Act: Call the sign_up function
            result = sign_up(email, password)

            # Assert: Check if the sign-up was successful
            assert result["success"] == expected_success


@pytest.mark.parametrize(
    "email, password, expected_success",
    [
        ("wrong@example.com", "WrongPassword", False),
    ],
)
def test_log_in_failure(email, password, expected_success):
    # Arrange: Mock Supabase authentication with invalid credentials
    mock_sign_in = MagicMock()
    mock_sign_in.return_value = MagicMock(user=None)  # Simulate failed login

    # Mock the response from the user_keys table for the salt
    mock_salt_response = MagicMock()
    mock_salt_response.data = []

    with patch(
        "modules.supabase_client.supabase.auth.sign_in_with_password", mock_sign_in
    ):
        with patch("modules.supabase_client.supabase.table") as mock_table:
            mock_table.return_value.select.return_value.eq.return_value.execute.return_value = (
                mock_salt_response
            )

            # Act: Call the log_in function
            result = log_in(email, password)

            # Assert: Check if the login failed
            assert result["success"] == expected_success
            assert result["message"] == "Invalid email or password."


@pytest.mark.parametrize(
    "email, password, expected_success",
    [
        ("test@example.com", "SecurePassword1", False),
    ],
)
def test_log_in_no_salt(email, password, expected_success):
    # Arrange: Mock Supabase authentication with valid credentials
    mock_sign_in = MagicMock()
    mock_sign_in.return_value = MagicMock(
        user=MagicMock(id=str(uuid.uuid4()), email=email)
    )

    # Mock the response from the user_keys table for missing salt
    mock_salt_response = MagicMock()
    mock_salt_response.data = []  # No encryption salt found

    with patch(
        "modules.supabase_client.supabase.auth.sign_in_with_password", mock_sign_in
    ):
        with patch("modules.supabase_client.supabase.table") as mock_table:
            mock_table.return_value.select.return_value.eq.return_value.execute.return_value = (
                mock_salt_response
            )

            # Act: Call the log_in function
            result = log_in(email, password)

            # Assert: Check if the login failed due to missing encryption salt
            assert result["success"] == expected_success
            assert result["message"] == "Encryption salt not found."


@pytest.mark.parametrize(
    "email, password, expected_success",
    [
        ("wrong@example.com", "WrongPassword", False),
    ],
)
def test_log_in_invalid(email, password, expected_success):
    # Arrange: Mock Supabase authentication with failure
    mock_sign_in = MagicMock()
    mock_sign_in.return_value = None  # Simulate failed login

    with patch(
        "modules.supabase_client.supabase.auth.sign_in_with_password", mock_sign_in
    ):
        # Act: Call the log_in function
        result = log_in(email, password)

        # Assert: Ensure login fails
        assert result["success"] == expected_success


def test_log_in_missing_salt():
    email = "test@example.com"
    password = "SecurePassword1"

    # Arrange: Mock the response to simulate missing salt
    mock_sign_in = MagicMock()
    mock_sign_in.return_value = MagicMock(
        user=MagicMock(id=str(uuid.uuid4()), email=email)
    )

    mock_salt_response = MagicMock()
    mock_salt_response.data = []  # Simulate missing salt

    with patch(
        "modules.supabase_client.supabase.auth.sign_in_with_password", mock_sign_in
    ):
        with patch("modules.supabase_client.supabase.table") as mock_table:
            mock_table.return_value.select.return_value.eq.return_value.execute.return_value = (
                mock_salt_response
            )

            # Act: Call the log_in function
            result = log_in(email, password)

            # Assert: Ensure the system handles missing salt
            assert result["success"] == False
            assert result["message"] == "Encryption salt not found."


def test_log_out_success():
    # Arrange: Mock the log-out functionality
    mock_sign_out = MagicMock()
    mock_sign_out.return_value = True

    with patch("modules.supabase_client.supabase.auth.sign_out", mock_sign_out):
        # Act: Call the log_out function
        result = log_out()

        # Assert: Ensure successful log out
        assert result["success"] == True
        assert (
            result["message"] == "Logged out successfully."
        )  # Updated to match with period


def test_log_out_failure():
    # Arrange: Mock the log-out failure
    mock_sign_out = MagicMock()
    mock_sign_out.side_effect = Exception("Unexpected error")

    with patch("modules.supabase_client.supabase.auth.sign_out", mock_sign_out):
        # Act: Call the log_out function
        result = log_out()

        # Assert: Ensure logout fails
        assert result["success"] == False
        assert result["message"] == "Logout error: Unexpected error"


def test_get_current_user():
    # Arrange: Mock the response for getting the current user
    mock_user = MagicMock(id="123", email="test@example.com")
    mock_get_user = MagicMock()
    mock_get_user.return_value = mock_user

    with patch("modules.supabase_client.supabase.auth.get_user", mock_get_user):
        # Act: Call the get_current_user function
        user = get_current_user()

        # Assert: Ensure the current user is returned
        assert user.id == "123"
        assert user.email == "test@example.com"


def test_is_logged_in():
    # Arrange: Mock the response for is_logged_in
    mock_get_user = MagicMock()
    mock_get_user.return_value = MagicMock(id="123", email="test@example.com")

    with patch("modules.supabase_client.supabase.auth.get_user", mock_get_user):
        # Act: Check if the user is logged in
        logged_in = is_logged_in()

        # Assert: Ensure the user is logged in
        assert logged_in == True


@pytest.mark.parametrize(
    "email, expected_success",
    [
        ("nonexistent@example.com", False),
    ],
)
def test_request_password_reset_failure(email, expected_success):
    # Mock user check query (no user found)
    mock_check_user = MagicMock()
    mock_check_user.return_value = MagicMock(data=[])

    # Mock `reset_password_for_email` to ensure it's never called
    mock_reset = MagicMock()

    with patch("modules.supabase_client.supabase.schema") as mock_schema:
        mock_table = mock_schema.return_value.table
        mock_table.return_value.select.return_value.eq.return_value.execute.return_value = MagicMock(
            data=[]
        )

        with patch(
            "modules.supabase_client.supabase.auth.reset_password_for_email", mock_reset
        ):
            # Act: Call the password reset function
            result = request_password_reset(email)

            # Assert: Ensure password reset fails
            assert result["success"] == expected_success
            assert result["message"] == "The entered email is not registered."

            # Ensure `reset_password_for_email` was **not** called
            mock_reset.assert_not_called()


def test_request_password_reset_success():
    email = "test@example.com"

    # Mock user check query (user exists)
    mock_rpc = MagicMock()
    mock_rpc.return_value.execute.return_value = MagicMock(data=[{"id": "123"}])

    # Mock sending the OTP (simulate success)
    mock_reset_password = MagicMock()
    mock_reset_password.return_value = None

    with patch("modules.supabase_client.supabase.rpc", mock_rpc):
        with patch(
            "modules.supabase_client.supabase.auth.reset_password_for_email",
            mock_reset_password,
        ):
            # Act: Call the password reset function
            result = request_password_reset(email)

            # Debugging: Print result to understand the returned value
            print(result)

            # Assert: Ensure password reset is successful
            assert (
                result["success"] == True
            ), f"Expected True, but got {result['success']}"
