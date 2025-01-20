import os
import sys

from cryptography.fernet import Fernet
from dotenv import load_dotenv
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QApplication, QDialog, QLabel, QLineEdit,
                             QMainWindow, QMessageBox, QPushButton,
                             QTableWidget, QTableWidgetItem, QVBoxLayout,
                             QWidget)

from modules.models import Password, SessionLocal
from modules.password_manager import (add_password, list_passwords,
                                      verify_master_password)

session = SessionLocal()

# Load environment variables
load_dotenv()
encryption_key = os.getenv("ENCRYPTION_KEY")
if not encryption_key:
    raise EnvironmentError("ENCRYPTION_KEY not found in .env file. Please set it.")
cipher = Fernet(encryption_key)

stored_encrypted_password = os.getenv("ENCRYPTED_MASTER_PASSWORD")
if not stored_encrypted_password:
    raise EnvironmentError("ENCRYPTED_MASTER_PASSWORD not found in .env file.")


class MasterPasswordDialog(QDialog):
    """Dialog to prompt the user for the master password."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Master Password")
        self.setGeometry(400, 300, 300, 150)

        layout = QVBoxLayout()

        # Label and input field for the master password
        self.label = QLabel("Enter your master password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)  # Hide text for security

        # Submit and Cancel buttons
        self.submit_button = QPushButton("Submit")
        self.cancel_button = QPushButton("Cancel")

        # Add widgets to the layout
        layout.addWidget(self.label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.submit_button)
        layout.addWidget(self.cancel_button)

        self.setLayout(layout)

        # Connect buttons to their respective functions
        self.submit_button.clicked.connect(self.validate_password)
        self.cancel_button.clicked.connect(self.reject)

    def validate_password(self):
        """Validate the entered master password."""
        input_password = self.password_input.text()

        # Check if the entered master password is correct
        if verify_master_password(
            input_password,
            stored_encrypted_password.encode(),
            encryption_key.encode(),
        ):
            self.accept()  # Close the dialog and proceed to the main application
        else:
            QMessageBox.critical(self, "Error", "Incorrect master password.")
            self.password_input.clear()


class AddPasswordDialog(QDialog):
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

        # Save and Cancel buttons
        self.save_button = QPushButton("Save")
        self.cancel_button = QPushButton("Cancel")

        # Add widgets to the layout
        layout.addWidget(self.service_label)
        layout.addWidget(self.service_input)
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.save_button)
        layout.addWidget(self.cancel_button)

        self.setLayout(layout)

        # Connect buttons to their respective functions
        self.save_button.clicked.connect(self.save_password)
        self.cancel_button.clicked.connect(self.close)

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


class PasswordTable(QTableWidget):
    """Widget to display stored passwords with View and Delete options."""

    def __init__(self, password_list, cipher):
        super().__init__(
            len(password_list), 4  # 4 columns: Service, Username, View, Delete
        )
        self.setHorizontalHeaderLabels(
            ["Service", "Username", "", ""]
        )  # Set column headers
        self.cipher = cipher  # Store the cipher for decryption

        # Populate the table rows
        for row, password_str in enumerate(password_list):
            # Parse the string to extract service and username
            service = self.extract_field(password_str, "Service")
            username = self.extract_field(password_str, "Username")

            # Add service and username to the table
            self.setItem(row, 0, QTableWidgetItem(service))
            self.setItem(row, 1, QTableWidgetItem(username))

            # Add "View" button
            view_button = QPushButton("View")
            view_button.clicked.connect(lambda _, r=row: self.handle_view_click(r))
            self.setCellWidget(row, 2, view_button)

            # Add "Delete" button
            delete_button = QPushButton("Delete")
            delete_button.clicked.connect(lambda _, r=row: self.handle_delete_click(r))
            self.setCellWidget(row, 3, delete_button)

        self.resizeColumnsToContents()

    def handle_view_click(self, row):
        """Handle the View button click to reveal and copy the password."""
        service = self.item(row, 0).text()
        username = self.item(row, 1).text()

        try:
            # Query the database for the clicked service
            password_data = (
                session.query(Password).filter_by(service_name=service).first()
            )
            if not password_data:
                QMessageBox.warning(
                    self, "Not Found", "No password found for this service."
                )
                return

            # Decrypt and display the password
            decrypted_password = password_data.get_decrypted_password(self.cipher)

            # Create a dialog to display the password with a Copy button
            dialog = QDialog(self)
            dialog.setWindowTitle("Password Revealed")
            dialog.setGeometry(300, 300, 400, 200)

            layout = QVBoxLayout(dialog)

            # Display service, username, and password
            layout.addWidget(QLabel(f"Service: {service}"))
            layout.addWidget(QLabel(f"Username: {username}"))
            layout.addWidget(QLabel(f"Password: {decrypted_password}"))

            # Add a Copy button
            copy_button = QPushButton("Copy Password")
            layout.addWidget(copy_button)

            # Connect the Copy button to copy the password to the clipboard
            copy_button.clicked.connect(
                lambda: self.copy_to_clipboard(decrypted_password)
            )

            dialog.setLayout(layout)
            dialog.exec_()  # Show the dialog

        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to retrieve password: {str(e)}"
            )

    def copy_to_clipboard(self, password):
        """Copy the given password to the clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(password)
        QMessageBox.information(self, "Copied", "Password copied to clipboard!")

    def handle_delete_click(self, row):
        """Handle the Delete button click to remove a password."""
        service = self.item(row, 0).text()

        # Confirmation dialog
        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete the password for {service}?",
            QMessageBox.Yes | QMessageBox.No,
        )

        if reply == QMessageBox.Yes:
            try:
                # Query the database and delete the password
                password_data = (
                    session.query(Password).filter_by(service_name=service).first()
                )
                if password_data:
                    session.delete(password_data)
                    session.commit()
                    QMessageBox.information(
                        self, "Deleted", f"Password for {service} deleted successfully."
                    )
                    self.removeRow(row)  # Remove the row from the table
                else:
                    QMessageBox.warning(
                        self, "Not Found", "No password found for this service."
                    )

            except Exception as e:
                QMessageBox.critical(
                    self, "Error", f"Failed to delete password: {str(e)}"
                )

    @staticmethod
    def extract_field(password_str, field_name):
        """Extract the value of a field (e.g., 'Service') from a string."""
        field_prefix = f"{field_name}: "
        start = password_str.find(field_prefix) + len(field_prefix)
        end = (
            password_str.find(",", start)
            if "," in password_str[start:]
            else len(password_str)
        )
        return password_str[start:end].strip()


class MainWindow(QMainWindow):
    """Main application window for the password manager."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 600, 400)

        # Main layout
        central_widget = QWidget()
        layout = QVBoxLayout()

        # Buttons for adding and listing passwords
        self.add_password_btn = QPushButton("Add Password")
        self.list_passwords_btn = QPushButton("List Passwords")

        # Status label for feedback
        self.status_label = QLabel("Welcome to Password Manager")
        self.status_label.setAlignment(Qt.AlignCenter)

        # Add widgets to the layout
        layout.addWidget(self.status_label)
        layout.addWidget(self.add_password_btn)
        layout.addWidget(self.list_passwords_btn)

        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        # Connect buttons to their respective functions
        self.add_password_btn.clicked.connect(self.open_add_password_dialog)
        self.list_passwords_btn.clicked.connect(self.display_passwords)

    def open_add_password_dialog(self):
        """Open the dialog for adding a new password."""
        dialog = AddPasswordDialog()
        dialog.exec_()

    def display_passwords(self):
        """Display a table of stored passwords."""
        try:
            password_list = list_passwords()  # Get the list of strings

            if isinstance(password_list, str):  # Handle "No passwords stored yet."
                QMessageBox.information(self, "No Passwords", password_list)
                return

            # Create a dialog to display the password table
            dialog = QDialog(self)
            dialog.setWindowTitle("Stored Passwords")
            dialog.setGeometry(200, 200, 600, 400)

            # Add the PasswordTable to the dialog
            layout = QVBoxLayout(dialog)
            table = PasswordTable(password_list, cipher)
            layout.addWidget(table)

            dialog.setLayout(layout)
            dialog.exec_()  # Show the dialog

        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to retrieve passwords: {str(e)}"
            )


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Show the master password dialog first
    password_dialog = MasterPasswordDialog()
    if password_dialog.exec_() == QDialog.Accepted:
        # If the master password is correct, show the main application window
        main_window = MainWindow()
        main_window.show()
        sys.exit(app.exec_())
    else:
        # If the dialog is rejected, exit the application
        sys.exit(0)
