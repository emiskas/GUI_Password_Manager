import os
import sys

from cryptography.fernet import Fernet
from dotenv import load_dotenv
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QApplication, QDialog, QLabel, QLineEdit,
                             QMainWindow, QMessageBox, QPushButton,
                             QTableWidget, QTableWidgetItem, QVBoxLayout,
                             QWidget)

from modules.password_manager import add_password, list_passwords

# Load environment variables
load_dotenv()
encryption_key = os.getenv("ENCRYPTION_KEY")
if not encryption_key:
    raise EnvironmentError("ENCRYPTION_KEY not found in .env file. Please set it.")
cipher = Fernet(encryption_key)


class AddPasswordDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Add Password")
        self.setGeometry(200, 200, 400, 300)

        layout = QVBoxLayout()

        # Input fields
        self.service_label = QLabel("Service Name:")
        self.service_input = QLineEdit()
        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()

        # Buttons
        self.save_button = QPushButton("Save")
        self.cancel_button = QPushButton("Cancel")

        # Add widgets to layout
        layout.addWidget(self.service_label)
        layout.addWidget(self.service_input)
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.save_button)
        layout.addWidget(self.cancel_button)

        self.setLayout(layout)

        # Button connections
        self.save_button.clicked.connect(self.save_password)
        self.cancel_button.clicked.connect(self.close)

    def save_password(self):
        service = self.service_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

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
    def __init__(self, password_list):
        super().__init__(
            len(password_list), 2
        )  # Number of rows = number of strings, 2 columns
        self.setHorizontalHeaderLabels(["Service", "Username"])  # Set column headers

        # Populate table rows
        for row, password_str in enumerate(password_list):
            # Parse the string
            service = self.extract_field(password_str, "Service")
            username = self.extract_field(password_str, "Username")

            # Populate the table with parsed values
            self.setItem(row, 0, QTableWidgetItem(service))
            self.setItem(row, 1, QTableWidgetItem(username))

        self.resizeColumnsToContents()

    @staticmethod
    def extract_field(password_str, field_name):
        """Extract the value of a field (e.g., 'Service') from the string."""
        field_prefix = f"{field_name}: "
        start = password_str.find(field_prefix) + len(field_prefix)
        end = (
            password_str.find(",", start)
            if "," in password_str[start:]
            else len(password_str)
        )
        return password_str[start:end].strip()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 600, 400)

        # Main layout
        central_widget = QWidget()
        layout = QVBoxLayout()

        # Buttons
        self.add_password_btn = QPushButton("Add Password")
        self.list_passwords_btn = QPushButton("List Passwords")

        # Status Label
        self.status_label = QLabel("Welcome to Password Manager")
        self.status_label.setAlignment(Qt.AlignCenter)

        # Add to layout
        layout.addWidget(self.status_label)
        layout.addWidget(self.add_password_btn)
        layout.addWidget(self.list_passwords_btn)

        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        # Button connections
        self.add_password_btn.clicked.connect(self.open_add_password_dialog)
        self.list_passwords_btn.clicked.connect(self.display_passwords)

    def open_add_password_dialog(self):
        dialog = AddPasswordDialog()
        dialog.exec_()

    def display_passwords(self):
        try:
            password_list = list_passwords()  # Get the list of strings

            if isinstance(password_list, str):  # Handle "No passwords stored yet."
                QMessageBox.information(self, "No Passwords", password_list)
                return

            # Create a dialog to display the table
            dialog = QDialog(self)
            dialog.setWindowTitle("Stored Passwords")
            dialog.setGeometry(200, 200, 600, 400)

            # Add the PasswordTable to the dialog
            layout = QVBoxLayout(dialog)
            table = PasswordTable(password_list)
            layout.addWidget(table)

            dialog.setLayout(layout)
            dialog.exec_()  # Show the dialog

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to retrieve passwords: {str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())
