from PyQt5.QtWidgets import (
    QApplication,
    QDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from modules.supabase_client import supabase
from modules.utils import (
    add_password,
    encrypt_password,
    generate_password,
    get_user_id
)


class BasePasswordDialog(QDialog):
    """Base class for password dialogs with shared functionalities."""

    @staticmethod
    def add_generated_password(password_input):
        """Generate a random password and set it in the input field."""
        try:
            # Generate a new password
            new_password = generate_password()

            # Set the new password in the field
            password_input.setText(new_password)

            QMessageBox.information(
                None, "Generated", "New password has been generated!"
            )
        except Exception as e:
            QMessageBox.warning(
                None,
                "Generation Error",
                f"Failed to generate password: {str(e)}"
            )


class AddPasswordDialog(BasePasswordDialog):
    """Dialog for adding a new password to Supabase."""

    def __init__(self, user_id):
        super().__init__()
        self.setWindowTitle("Add Password")
        self.setGeometry(200, 200, 400, 300)

        # Store user_id for database queries
        self.user_id = user_id

        layout = QVBoxLayout()

        # Input fields
        self.service_label = QLabel("Service Name:")
        self.service_input = QLineEdit()
        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        # Buttons
        self.save_button = QPushButton("Save")
        self.generate_button = QPushButton("Generate Password")
        self.exit_button = QPushButton("Exit")

        # Add widgets
        layout.addWidget(self.service_label)
        layout.addWidget(self.service_input)
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.save_button)
        layout.addWidget(self.generate_button)
        layout.addWidget(self.exit_button)

        self.setLayout(layout)

        # Button connections
        self.save_button.clicked.connect(self.save_password)
        self.generate_button.clicked.connect(
            lambda: self.add_generated_password(self.password_input)
        )
        self.exit_button.clicked.connect(self.close)

    def save_password(self):
        service = self.service_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not service or not username or not password:
            QMessageBox.warning(self, "Error", "All fields are required.")
            return

        try:
            user_id = get_user_id()
            if not user_id:
                QMessageBox.critical(self, "Error", "Authentication failed")
                return

            try:
                result = add_password(service, username, password)["message"]
            except supabase.PostgrestError as db_error:
                QMessageBox.critical(
                    self,
                    "Database Error",
                    f"Database connection failed: {str(db_error)}",
                )
                return
            except TimeoutError:
                QMessageBox.critical(
                    self,
                    "Connection Error",
                    "Database connection timed out. Please try again.",
                )
                return

            if "success" in result.lower():
                QMessageBox.information(
                    self, "Success", f"Password for {service} added."
                )
                self.close()
            else:
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to add password: {result}"
                )

        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to add password: {str(e)}"
            )


class UpdatePasswordDialog(BasePasswordDialog):
    """Dialog for viewing, updating, and deleting a password."""

    def __init__(
            self,
            user_id,
            service,
            username,
            encrypted_password,
            row,
            parent_table
    ):
        super().__init__()
        self.setWindowTitle("Update Password")
        self.setGeometry(300, 300, 400, 300)

        self.user_id = user_id
        self.row = row
        self.parent_table = parent_table
        self.original_service = service
        self.original_username = username

        self.updated_service = None
        self.updated_username = None

        layout = QVBoxLayout()

        # Fields
        self.service_label = QLabel("Service Name:")
        self.service_input = QLineEdit(service)

        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit(username)

        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit(
            encrypted_password["decrypted_password"]
        )
        self.password_input.setEchoMode(QLineEdit.Password)

        # Buttons
        self.toggle_password_btn = QPushButton("Show Password")
        self.toggle_password_btn.setCheckable(True)
        self.toggle_password_btn.clicked.connect(
            self.toggle_password_visibility
        )

        self.generate_button = QPushButton("Generate Password")
        self.copy_button = QPushButton("Copy Password")
        self.update_button = QPushButton("Save")
        self.delete_button = QPushButton("Delete")
        self.exit_button = QPushButton("Exit")

        # Add widgets
        layout.addWidget(self.service_label)
        layout.addWidget(self.service_input)
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.toggle_password_btn)
        layout.addWidget(self.copy_button)
        layout.addWidget(self.generate_button)
        layout.addWidget(self.update_button)
        layout.addWidget(self.delete_button)
        layout.addWidget(self.exit_button)

        self.setLayout(layout)

        # Button connections
        self.generate_button.clicked.connect(
            lambda: self.add_generated_password(self.password_input)
        )
        self.copy_button.clicked.connect(
            lambda: self.copy_to_clipboard(encrypted_password)
        )
        self.update_button.clicked.connect(self.update_password)
        self.delete_button.clicked.connect(self.delete_password)
        self.exit_button.clicked.connect(self.reject)

    def toggle_password_visibility(self):
        """Toggle password visibility."""
        try:
            if self.toggle_password_btn.isChecked():
                self.password_input.setEchoMode(QLineEdit.Normal)
                self.toggle_password_btn.setText("Hide Password")
            else:
                self.password_input.setEchoMode(QLineEdit.Password)
                self.toggle_password_btn.setText("Show Password")
        except Exception as e:
            QMessageBox.warning(
                self,
                "UI Error",
                f"Failed to toggle password visibility: {str(e)}"
            )

    def copy_to_clipboard(self, password):
        """Copy password to clipboard."""
        try:
            clipboard = QApplication.clipboard()
            clipboard.setText(password)
            QMessageBox.information(
                self,
                "Copied",
                "Password copied to clipboard!"
            )
        except Exception as e:
            QMessageBox.warning(
                self,
                "Clipboard Error",
                f"Failed to copy to clipboard: {str(e)}"
            )

    def update_password(self):
        """Update the password in Supabase."""
        new_service = self.service_input.text().strip()
        new_username = self.username_input.text().strip()
        new_password = self.password_input.text().strip()

        if not new_service or not new_username or not new_password:
            QMessageBox.warning(self, "Error", "All fields are required.")
            return

        try:
            # First try to get the encryption key with timeout handling
            try:
                response = (
                    supabase.table("user_keys")
                    .select("encryption_salt")
                    .eq("user_id", self.user_id)
                    .single()
                    .execute()
                )
                if not response.data:
                    QMessageBox.warning(
                        self,
                        "Error",
                        "Encryption key not found for this user."
                    )
                    return
            except TimeoutError:
                QMessageBox.critical(
                    self,
                    "Connection Error",
                    "Database connection timed out. Please try again.",
                )
                return
            except supabase.PostgrestError as db_error:
                QMessageBox.critical(
                    self,
                    "Database Error",
                    f"Failed to query database: {str(db_error)}"
                )
                return
            except Exception as key_error:
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to retrieve encryption key: {str(key_error)}",
                )
                return

            user_key = response.data["encryption_salt"]

            try:
                encrypted_password = encrypt_password(new_password, user_key)
                if (
                    not encrypted_password or len(encrypted_password) < 10
                ):
                    QMessageBox.warning(
                        self,
                        "Encryption Error",
                        "Password encryption failed. Please try again.",
                    )
                    return
            except Exception as encrypt_error:
                QMessageBox.critical(
                    self,
                    "Encryption Error",
                    f"Failed to encrypt password: {str(encrypt_error)}",
                )
                return

            try:
                response = (
                    supabase.table("passwords")
                    .update(
                        {
                            "service_name": new_service,
                            "username": new_username,
                            "encrypted_password": encrypted_password,
                        }
                    )
                    .eq("user_id", self.user_id)
                    .eq("service_name", self.original_service)
                    .eq("username", self.original_username)
                    .execute()
                )

                if not response or not response.data:
                    QMessageBox.warning(
                        self,
                        "Warning",
                        "Update may not have been successful. Please verify.",
                    )
                    return

                self.updated_service = new_service
                self.updated_username = new_username

                QMessageBox.information(
                    self, "Success", "Password updated successfully."
                )
                self.accept()
            except TimeoutError:
                QMessageBox.critical(
                    self,
                    "Connection Error",
                    "Database update timed out. Please try again.",
                )
            except supabase.PostgrestError as db_error:
                QMessageBox.critical(
                    self,
                    "Database Error",
                    f"Failed to update password: {str(db_error)}",
                )
            except Exception as update_error:
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to update password: {str(update_error)}"
                )

        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to update password: {str(e)}"
            )

    def delete_password(self):
        """Delete the password entry from Supabase."""
        confirm = QMessageBox.question(
            self,
            "Confirm Delete",
            "Are you sure you want to delete this password?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        if confirm == QMessageBox.Yes:
            try:
                try:
                    response = (
                        supabase.table("passwords")
                        .delete()
                        .eq("user_id", self.user_id)
                        .eq("service_name", self.original_service)
                        .eq("username", self.original_username)
                        .execute()
                    )

                    # Verify deletion was successful by checking response
                    if not response or not response.data:
                        QMessageBox.warning(
                            self,
                            "Warning",
                            "Password may not have been deleted. "
                            "Please verify.",
                        )
                        return
                except TimeoutError:
                    QMessageBox.critical(
                        self,
                        "Connection Error",
                        "Database deletion timed out. Please try again.",
                    )
                    return
                except supabase.PostgrestError as db_error:
                    QMessageBox.critical(
                        self,
                        "Database Error",
                        f"Failed to delete from database: {str(db_error)}",
                    )
                    return

                try:
                    # Remove the row from the table
                    self.parent_table.removeRow(self.row)
                except Exception as ui_error:
                    QMessageBox.warning(
                        self,
                        "UI Error",
                        f"Password was deleted but UI update failed: "
                        f"{str(ui_error)}",
                    )
                    self.accept()
                    return

                QMessageBox.information(
                    self, "Deleted", "Password deleted successfully."
                )
                self.accept()

            except Exception as e:
                QMessageBox.critical(
                    self, "Error", f"Failed to delete password: {str(e)}"
                )


if __name__ == "__main__":
    import sys

    try:
        app = QApplication(sys.argv)

        try:
            user_id = get_user_id()
            if not user_id:
                QMessageBox.critical(
                    None,
                    "Error",
                    "You must be logged in to manage passwords."
                )
                sys.exit(1)
        except Exception as auth_error:
            QMessageBox.critical(
                None,
                "Authentication Error",
                f"Failed to verify user: {str(auth_error)}",
            )
            sys.exit(1)

        dialog = AddPasswordDialog(user_id)
        dialog.exec_()

        sys.exit(app.exec_())
    except Exception as e:
        QMessageBox.critical(
            None, "Fatal Error", f"Application failed to start: {str(e)}"
        )
        sys.exit(1)
