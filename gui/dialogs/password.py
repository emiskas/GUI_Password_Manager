from PyQt5.QtWidgets import (QApplication, QDialog, QLabel, QLineEdit,
                             QMessageBox, QPushButton, QVBoxLayout)

from modules.supabase_client import supabase
from modules.utils import add_password, generate_password, get_user_id, encrypt_password


class BasePasswordDialog(QDialog):
    """Base class for password dialogs with shared functionalities."""

    @staticmethod
    def add_generated_password(password_input):
        """Generate a random password and set it in the input field."""
        new_password = generate_password()  # Generate a new password
        password_input.setText(new_password)  # Set the new password in the field
        QMessageBox.information(None, "Generated", "New password has been generated!")


class AddPasswordDialog(BasePasswordDialog):
    """Dialog for adding a new password to Supabase."""

    def __init__(self, user_id):
        super().__init__()
        self.setWindowTitle("Add Password")
        self.setGeometry(200, 200, 400, 300)

        self.user_id = user_id  # Store user_id for database queries

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

            result = add_password(service, username, password)

            if "success" in result.lower():
                QMessageBox.information(
                    self, "Success", f"Password for {service} added."
                )
                self.close()
            else:
                QMessageBox.critical(self, "Error", f"Failed to add password: {result}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add password: {str(e)}")


class UpdatePasswordDialog(BasePasswordDialog):
    """Dialog for viewing, updating, and deleting a password."""

    def __init__(
        self, user_id, service, username, encrypted_password, row, parent_table
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
        self.password_input = QLineEdit(encrypted_password)
        self.password_input.setEchoMode(QLineEdit.Password)

        # Buttons
        self.toggle_password_btn = QPushButton("Show Password")
        self.toggle_password_btn.setCheckable(True)
        self.toggle_password_btn.clicked.connect(self.toggle_password_visibility)

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
        if self.toggle_password_btn.isChecked():
            self.password_input.setEchoMode(QLineEdit.Normal)
            self.toggle_password_btn.setText("Hide Password")
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
            self.toggle_password_btn.setText("Show Password")

    def copy_to_clipboard(self, password):
        """Copy password to clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(password)
        QMessageBox.information(self, "Copied", "Password copied to clipboard!")

    def update_password(self):
        """Update the password in Supabase."""
        new_service = self.service_input.text().strip()
        new_username = self.username_input.text().strip()
        new_password = self.password_input.text().strip()

        # Fetch user's encryption key
        response = (
            supabase.table("user_keys")
            .select("encryption_salt")
            .eq("user_id", self.user_id)
            .single()
            .execute()
        )
        if not response.data:
            return "Error: Encryption key not found for this user."

        user_key = response.data["encryption_salt"]
        encrypted_password = encrypt_password(new_password, user_key)

        if not new_service or not new_username or not new_password:
            QMessageBox.warning(self, "Error", "All fields are required.")
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
            self.updated_service = new_service
            self.updated_username = new_username

            QMessageBox.information(self, "Success", "Password updated successfully.")
            self.accept()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update password: {str(e)}")

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
                response = (
                    supabase.table("passwords")
                    .delete()
                    .eq("user_id", self.user_id)
                    .eq("service_name", self.original_service)
                    .eq("username", self.original_username)
                    .execute()
                )

                QMessageBox.information(
                    self, "Deleted", "Password deleted successfully."
                )

                # Remove the row from the table
                self.parent_table.removeRow(self.row)

                self.accept()

            except Exception as e:
                QMessageBox.critical(
                    self, "Error", f"Failed to delete password: {str(e)}"
                )


if __name__ == "__main__":
    import sys

    app = QApplication(sys.argv)

    user_id = get_user_id()
    if not user_id:
        QMessageBox.critical(
            None, "Error", "You must be logged in to manage passwords."
        )
        sys.exit()

    dialog = AddPasswordDialog(user_id)
    dialog.exec_()

    sys.exit(app.exec_())
