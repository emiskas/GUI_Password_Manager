import os

from cryptography.fernet import Fernet
from dotenv import load_dotenv
from PyQt5.QtWidgets import (QApplication, QDialog, QLabel, QLineEdit,
                             QMessageBox, QPushButton, QVBoxLayout)

from modules.models import Password, SessionLocal
from modules.password_manager import add_password, generate_password

session = SessionLocal()

# Load environment variables
load_dotenv()

# Get the encryption key
encryption_key = os.getenv("ENCRYPTION_KEY")
cipher = Fernet(encryption_key)


class BasePasswordDialog(QDialog):
    """Base class for password dialogs with shared functionalities."""

    @staticmethod
    def add_generated_password(password_input):
        """Generate a random password and set it in the input field."""
        new_password = generate_password()  # Generate a new password
        password_input.setText(new_password)  # Set the new password in the field
        QMessageBox.information(None, "Generated", "New password has been generated!")


class AddPasswordDialog(BasePasswordDialog):
    """Dialog for adding a new password to the database."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Add Password")
        self.setGeometry(200, 200, 400, 300)

        layout = QVBoxLayout()

        # Input fields for service name, username, and password
        self.service_label = QLabel("Service Name:")
        self.service_input = QLineEdit()
        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()

        # Buttons
        self.save_button = QPushButton("Save")
        self.generate_button = QPushButton("Generate Password")
        self.exit_button = QPushButton("Exit")

        # Add widgets to the layout
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

        # Connect buttons to their respective functions
        self.save_button.clicked.connect(self.save_password)
        self.generate_button.clicked.connect(
            lambda: self.add_generated_password(self.password_input)
        )
        self.exit_button.clicked.connect(self.close)

    def save_password(self):
        """Save the entered password to the database."""
        service = self.service_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        # Ensure all fields are filled
        if not service or not username or not password:
            QMessageBox.warning(self, "Error", "All fields are required.")
            return

        try:
            add_password(service, username, password, cipher)
            QMessageBox.information(self, "Success", f"Password for {service} added.")
            self.close()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add password: {str(e)}")


class UpdatePasswordDialog(BasePasswordDialog):
    """Dialog for viewing, updating, and deleting a password."""

    def __init__(self, service, username, password, cipher, row, parent_table):
        super().__init__()
        self.setWindowTitle("Update Password")
        self.setGeometry(300, 300, 400, 300)

        self.cipher = cipher
        self.row = row
        self.parent_table = parent_table
        self.updated_service = service
        self.updated_username = username

        layout = QVBoxLayout()

        # Current service and username
        self.service_label = QLabel("Service Name:")
        self.service_input = QLineEdit()
        self.service_input.setText(service)

        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        self.username_input.setText(username)

        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setText(password)
        self.password_input.setEchoMode(QLineEdit.Password)  # Conceal password

        # Show/Hide password toggle
        self.toggle_password_btn = QPushButton("Show Password")
        self.toggle_password_btn.setCheckable(True)
        self.toggle_password_btn.clicked.connect(self.toggle_password_visibility)

        # Buttons
        self.generate_button = QPushButton("Generate Password")
        self.copy_button = QPushButton("Copy Password")
        self.update_button = QPushButton("Save")
        self.delete_button = QPushButton("Delete")
        self.exit_button = QPushButton("Exit")

        # Add widgets to layout
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
        self.copy_button.clicked.connect(lambda: self.copy_to_clipboard(password))
        self.update_button.clicked.connect(self.update_password)
        self.delete_button.clicked.connect(self.delete_password)
        self.exit_button.clicked.connect(self.reject)

    def toggle_password_visibility(self):
        """Toggle the visibility of the password."""
        if self.toggle_password_btn.isChecked():
            self.password_input.setEchoMode(QLineEdit.Normal)
            self.toggle_password_btn.setText("Hide Password")
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
            self.toggle_password_btn.setText("Show Password")

    def copy_to_clipboard(self, password):
        """Copy the given password to the clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(password)
        QMessageBox.information(self, "Copied", "Password copied to clipboard!")

    def update_password(self):
        """Update the password in the database."""
        new_service = self.service_input.text().strip()
        new_username = self.username_input.text().strip()
        new_password = self.password_input.text().strip()

        if not new_service or not new_username or not new_password:
            QMessageBox.warning(self, "Error", "All fields are required.")
            return

        try:
            password_data = (
                session.query(Password)
                .filter_by(service_name=self.updated_service)
                .first()
            )
            if password_data:
                # Update the database entry
                password_data.service_name = new_service
                password_data.username = new_username
                password_data.set_encrypted_password(new_password, self.cipher)
                session.commit()

                # Update dialog attributes for the parent table
                self.updated_service = new_service
                self.updated_username = new_username

                QMessageBox.information(
                    self, "Success", "Password updated successfully."
                )
                self.accept()  # Close the dialog
            else:
                QMessageBox.warning(
                    self, "Not Found", "Password not found in the database."
                )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update password: {str(e)}")

    def delete_password(self):
        """Delete the password from the database."""
        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete the password for {self.updated_service}?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            try:
                password_data = (
                    session.query(Password)
                    .filter_by(service_name=self.updated_service)
                    .first()
                )
                if password_data:
                    session.delete(password_data)
                    session.commit()

                    # Remove the row from the parent table
                    self.parent_table.removeRow(self.row)

                    QMessageBox.information(
                        self,
                        "Deleted",
                        f"Password for {self.updated_service} deleted successfully.",
                    )
                    self.accept()  # Close the dialog
                else:
                    QMessageBox.warning(
                        self, "Not Found", "Password not found in the database."
                    )
            except Exception as e:
                QMessageBox.critical(
                    self, "Error", f"Failed to delete password: {str(e)}"
                )
