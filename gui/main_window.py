import os
import sys

from cryptography.fernet import Fernet
from dotenv import load_dotenv
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QApplication,
    QDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from modules.models import Password, SessionLocal
from modules.password_manager import (
    add_password,
    list_passwords,
    set_master_password,
    verify_master_password,
)

session = SessionLocal()

# Load environment variables
load_dotenv()
encryption_key = os.getenv("ENCRYPTION_KEY")
if not encryption_key:
    raise EnvironmentError("ENCRYPTION_KEY not found in .env file. Please set it.")
cipher = Fernet(encryption_key)

stored_encrypted_password = os.getenv("ENCRYPTED_MASTER_PASSWORD")


# if not stored_encrypted_password:
#     raise EnvironmentError("ENCRYPTED_MASTER_PASSWORD not found in .env file.")


class MasterPasswordCreationDialog(QDialog):
    """Dialog to prompt the user to create a master password"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Master Password Creation")
        self.setGeometry(400, 300, 300, 150)

        layout = QVBoxLayout()

        # Label and input field for the master password
        self.label = QLabel("Choose a master password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)  # Hide text for security

        # Submit and Exit buttons
        self.submit_button = QPushButton("Submit")
        self.exit_button = QPushButton("Exit")

        # Add widgets to the layout
        layout.addWidget(self.label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.submit_button)
        layout.addWidget(self.exit_button)

        self.setLayout(layout)

        # Connect buttons to their respective functions
        self.submit_button.clicked.connect(self.create_master_password)
        self.exit_button.clicked.connect(self.reject)

    def create_master_password(self):
        """Save the master password and close the dialog."""
        master_password = self.password_input.text().strip()

        if not master_password:
            QMessageBox.warning(self, "Error", "Master password cannot be empty.")
            return

        try:
            set_master_password(master_password, encryption_key.encode())
            QMessageBox.information(
                self, "Success", "Master password created successfully."
            )
            self.accept()  # Close the dialog
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to set master password: {str(e)}"
            )


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

        # Submit and Exit buttons
        self.submit_button = QPushButton("Submit")
        self.exit_button = QPushButton("Exit")

        # Add widgets to the layout
        layout.addWidget(self.label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.submit_button)
        layout.addWidget(self.exit_button)

        self.setLayout(layout)

        # Connect buttons to their respective functions
        self.submit_button.clicked.connect(self.validate_password)
        self.exit_button.clicked.connect(self.reject)

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

        # Save and Exit buttons
        self.save_button = QPushButton("Save")
        self.exit_button = QPushButton("Exit")

        # Add widgets to the layout
        layout.addWidget(self.service_label)
        layout.addWidget(self.service_input)
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.save_button)
        layout.addWidget(self.exit_button)

        self.setLayout(layout)

        # Connect buttons to their respective functions
        self.save_button.clicked.connect(self.save_password)
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


class PasswordTable(QTableWidget):
    """Widget to display stored passwords with View options."""

    def __init__(self, password_list, cipher):
        super().__init__(len(password_list), 3)  # 3 columns: Service, Username, Actions
        self.setHorizontalHeaderLabels(
            ["Service", "Username", "Actions"]
        )  # Set column headers
        self.cipher = cipher  # Store the cipher for decryption

        # Set table properties
        self.setContentsMargins(0, 0, 0, 0)  # Ensure no margin around the table
        self.horizontalHeader().setStretchLastSection(True)  # Stretch last column
        self.horizontalHeader().setDefaultSectionSize(150)  # Adjust column sizes
        self.verticalHeader().setVisible(False)  # Hide row headers

        # Populate the table rows
        for row, password_str in enumerate(password_list):
            # Parse the string to extract service and username
            service = self.extract_field(password_str, "Service")
            username = self.extract_field(password_str, "Username")

            # Add service and username to the table
            service_item = QTableWidgetItem(service)
            username_item = QTableWidgetItem(username)

            # Make cells non-editable
            service_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
            username_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)

            self.setItem(row, 0, service_item)
            self.setItem(row, 1, username_item)

            # Add "View" button
            view_button = QPushButton("View")
            view_button.clicked.connect(lambda _, r=row: self.handle_view_click(r))
            self.setCellWidget(row, 2, view_button)

        self.resizeColumnsToContents()

    def handle_view_click(self, row):
        """Handle the View button click to open the UpdatePasswordDialog."""
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

            # Decrypt the password and open the update dialog
            decrypted_password = password_data.get_decrypted_password(self.cipher)
            dialog = UpdatePasswordDialog(
                service, username, decrypted_password, self.cipher, row, self
            )
            if dialog.exec_() == QDialog.Accepted:
                # Update the table with any changes made
                self.setItem(row, 0, QTableWidgetItem(dialog.updated_service))
                self.setItem(row, 1, QTableWidgetItem(dialog.updated_username))

        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to retrieve password: {str(e)}"
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


class UpdatePasswordDialog(QDialog):
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
        self.copy_button = QPushButton("Copy Password")
        self.update_button = QPushButton("Update")
        self.delete_button = QPushButton("Delete")
        self.exit_button = QPushButton("Exit")

        # Add widgets to layout
        layout.addWidget(self.service_label)
        layout.addWidget(self.service_input)
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.copy_button)
        layout.addWidget(self.toggle_password_btn)
        layout.addWidget(self.update_button)
        layout.addWidget(self.delete_button)
        layout.addWidget(self.exit_button)

        self.setLayout(layout)

        # Button connections
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


class MainWindow(QMainWindow):
    """Main application window for the password manager."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 400, 200)

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
            layout.setContentsMargins(0, 0, 0, 0)  # Remove margins
            layout.setSpacing(0)  # Remove spacing between widgets
            table = PasswordTable(password_list, cipher)
            layout.addWidget(table)

            dialog.setLayout(layout)
            dialog.exec_()  # Show the dialog

        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to retrieve passwords: {str(e)}"
            )


def is_windows_dark_mode():
    """Check if Windows is set to dark mode."""
    try:
        import winreg as reg  # Windows Registry module

        key = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        with reg.OpenKey(reg.HKEY_CURRENT_USER, key) as registry_key:
            value, _ = reg.QueryValueEx(registry_key, "AppsUseLightTheme")
            return value == 0  # 0 means dark mode, 1 means light mode
    except ImportError:
        return False  # Default to light mode if on a non-Windows system
    except Exception:
        return False  # Default to light mode in case of an error


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Check for dark mode on Windows
    dark_mode = is_windows_dark_mode()

    # Apply theme based on detection
    if dark_mode:
        app.setStyleSheet(
            """
            QMainWindow, QDialog {
                background-color: #2B2B2B;
                color: #EAEAEA;
            }
            QPushButton {
                background-color: #444444;
                color: #EAEAEA;
                border: 1px solid #555555;
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #555555;
            }
            QLabel {
                color: #EAEAEA;
            }
            QLineEdit {
                background-color: #3B3B3B;
                color: #EAEAEA;
                border: 1px solid #555555;
                padding: 3px;
                border-radius: 3px;
            }
            QTableWidget {
                background-color: #3B3B3B;
                color: #EAEAEA;
                gridline-color: #555555;
            }
            QHeaderView::section {
                background-color: #444444;
                color: #EAEAEA;
                padding: 4px;
                border: 1px solid #555555;
            }
            """
        )
    else:
        app.setStyleSheet(
            """
            QMainWindow, QDialog {
                background-color: #f0f0f0;
                color: #000000;
            }
            QPushButton {
                background-color: #ffffff;
                color: #000000;
                border: 1px solid #000000;
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
            QLabel {
                color: #000000;
            }
            QLineEdit {
                background-color: #ffffff;
                color: #000000;
                border: 1px solid #cccccc;
                padding: 3px;
                border-radius: 3px;
            }
            QTableWidget {
                background-color: #ffffff;
                color: #000000;
                gridline-color: #cccccc;
            }
            QHeaderView::section {
                background-color: #f0f0f0;
                color: #000000;
                padding: 4px;
                border: 1px solid #dddddd;
            }
            """
        )

    # Your main application logic
    if not os.getenv("ENCRYPTED_MASTER_PASSWORD"):
        creation_dialog = MasterPasswordCreationDialog()
        if creation_dialog.exec_() == QDialog.Accepted:
            load_dotenv()  # Reload to fetch the saved master password
            stored_encrypted_password = os.getenv("ENCRYPTED_MASTER_PASSWORD")
        else:
            sys.exit(0)

    password_dialog = MasterPasswordDialog()
    if password_dialog.exec_() == QDialog.Accepted:
        main_window = MainWindow()
        main_window.show()
        sys.exit(app.exec_())
    else:
        sys.exit(0)
