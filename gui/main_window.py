import json
import sys
from io import BytesIO

import qrcode
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QImage, QPixmap
from PyQt5.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gui.components.password_table import PasswordTable
from gui.dialogs.login import LoginDialog
from gui.dialogs.password import AddPasswordDialog
from modules.auth import get_current_user, log_out
from modules.supabase_client import supabase
from modules.utils import (
    decrypt_password,
    export_passwords,
    get_user_id,
    import_passwords,
    list_passwords,
)


class QRCodeDialog(QDialog):
    """Dialog to display QR Code dynamically."""

    def __init__(self, data):
        super().__init__()
        self.setWindowTitle("QR Code")
        self.setGeometry(300, 300, 300, 300)

        layout = QVBoxLayout()

        # Generate and display QR code
        self.qr_label = QLabel(self)
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.display_qr_code(data)

        layout.addWidget(self.qr_label)
        self.setLayout(layout)

    def display_qr_code(self, data):
        """Generate QR code and display it dynamically."""
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_Q,
            box_size=5,
            border=2,
        )
        qr.add_data(data)
        qr.make(fit=True)

        # Convert QR Code to an image in memory
        img = qr.make_image(fill="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)

        # Load the image into PyQt QLabel
        image = QImage()
        image.loadFromData(buffer.getvalue(), "PNG")
        pixmap = QPixmap.fromImage(image)

        self.qr_label.setPixmap(pixmap)


class MainWindow(QMainWindow):
    """Main application window for the password manager."""

    def __init__(self, user_id):
        super().__init__()
        self.user_id = user_id
        self.qr_dialog = None

        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 400, 200)

        # Main layout
        central_widget = QWidget()
        layout = QVBoxLayout()

        # Buttons for adding and listing passwords
        self.add_password_btn = QPushButton("Add Password")
        self.list_passwords_btn = QPushButton("List Passwords")
        self.export_passwords_btn = QPushButton("Export Passwords")
        self.import_passwords_btn = QPushButton("Import Passwords")
        self.qr_button = QPushButton("Export via QR Code")
        self.logout_button = QPushButton("Log Out")

        # Status label for feedback
        self.status_label = QLabel("Welcome to Password Manager")
        self.status_label.setAlignment(Qt.AlignCenter)

        # Add widgets to the layout
        layout.addWidget(self.status_label)
        layout.addWidget(self.add_password_btn)
        layout.addWidget(self.list_passwords_btn)
        layout.addWidget(self.export_passwords_btn)
        layout.addWidget(self.import_passwords_btn)
        layout.addWidget(self.qr_button)
        layout.addWidget(self.logout_button)

        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        # Connect buttons to their respective functions
        self.add_password_btn.clicked.connect(self.open_add_password_dialog)
        self.list_passwords_btn.clicked.connect(self.display_passwords)
        self.export_passwords_btn.clicked.connect(self.handle_export)
        self.import_passwords_btn.clicked.connect(self.handle_import)
        self.qr_button.clicked.connect(self.show_qr_code)
        self.logout_button.clicked.connect(self.handle_logout)

    def handle_logout(self):
        """Logs out the user and returns to the login screen."""
        try:
            log_out()
            QMessageBox.information(
                self,
                "Logged Out", "You have been logged out."
            )

            login_dialog = LoginDialog()

            self.close()

            login_dialog.exec_()

        except Exception as e:
            QMessageBox.critical(
                self,
                "Logout Error",
                f"Failed to log out: {str(e)}"
            )

    def show_qr_code(self):
        """Show QR Code dialog for stored passwords with encryption."""
        user_id = get_user_id()
        user_id = user_id["user_id"]

        if not user_id:
            QMessageBox.critical(
                self,
                "Error",
                "No authenticated user found."
            )
            return

        reply = QMessageBox.question(
            self,
            "Encrypt Export?",
            "Do you want to encrypt the exported passwords?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        if reply == QMessageBox.Yes:
            response = (
                supabase.table("passwords")
                .select("service_name, username, encrypted_password")
                .eq("user_id", user_id)
                .execute()
            )
        else:
            key_response = (
                supabase.table("user_keys")
                .select("encryption_salt")
                .eq("user_id", user_id)
                .single()
                .execute()
            )

            if (not key_response.data
                    or "encryption_salt" not in key_response.data):
                QMessageBox.critical(
                    self,
                    "Encryption Error",
                    "Could not retrieve encryption key."
                )
                return

            user_key = key_response.data["encryption_salt"]

            response = (
                supabase.table("passwords")
                .select(f"service_name, username, encrypted_password")
                .eq("user_id", user_id)
                .execute()
            )

            encrypted_password = response.data[0]["encrypted_password"]
            decrypted_password = decrypt_password(
                encrypted_password,
                user_key
            )
            response.data[0]["encrypted_password"] = decrypted_password[
                "decrypted_password"
            ]

        try:
            passwords = []
            for row in response.data:
                passwords.append(f"Service name: {row["service_name"]} "
                                 f"Username: {row["username"]} "
                                 f"Password: {row["encrypted_password"]}")

            for row in range(len(passwords)):
                split_row = passwords[row].split(" ")
                passwords[row] = split_row

            for row in range(len(passwords)):
                service = passwords[row][2]
                username = passwords[row][4]
                password = passwords[row][6]

                passwords[row] = (
                    f"Service name: {service}, "
                    f"Username: {username}, "
                    f"Password: {password}"
                )

            qr_data = "\n".join([
                f"Entry {i + 1}:\n{entry}\n" + "-" * 30
                for i, entry in enumerate(passwords)
            ])

            self.qr_dialog = QRCodeDialog(qr_data)
            self.qr_dialog.exec_()

        except json.JSONDecodeError:
            QMessageBox.critical(
                self,
                "QR Error",
                "Failed to generate QR code due to invalid data."
            )

        except Exception as e:
            QMessageBox.critical(
                self, 
                "QR Error",
                f"Unexpected error: {str(e)}"
            )

    def open_add_password_dialog(self):
        """Open the dialog for adding a new password."""
        dialog = AddPasswordDialog(user_id=self.user_id)
        dialog.exec_()

    def display_passwords(self):
        """Display a table of stored passwords."""
        try:
            response = list_passwords()

            if not response["success"]:
                raise ValueError(response["message"])

            password_list = response["data"]

            if not password_list:
                QMessageBox.information(
                    self, "No Passwords", "No passwords stored yet."
                )
                return

            dialog = QDialog(self)
            dialog.setWindowTitle("Stored Passwords")
            dialog.setGeometry(200, 200, 600, 400)

            layout = QVBoxLayout(dialog)
            table = PasswordTable(password_list)
            layout.addWidget(table)
            dialog.setLayout(layout)
            dialog.exec_()

        except ValueError as ve:
            QMessageBox.critical(
                self, 
                "Data Error", 
                f"Invalid data format: {str(ve)}"
            )
            
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to retrieve passwords: {str(e)}"
            )

    def handle_import(self):
        """Handle the import process."""
        try:
            selected_file, _ = QFileDialog.getOpenFileName(
                self,
                "Select Backup File",
                "backup",
                "Text Files (*.txt);;All Files (*)",
            )
            
            if not selected_file:
                return

            result = import_passwords(selected_file)
            QMessageBox.information(self, "Import Status", result["message"])

        except FileNotFoundError:
            QMessageBox.warning(self, "Import Error", "File not found.")
            
        except Exception as e:
            QMessageBox.critical(
                self, 
                "Import Error", 
                f"Failed to import: {str(e)}"
            )

    def handle_export(self):
        """Handle the export process with encryption option."""
        try:
            reply = QMessageBox.question(
                self,
                "Encrypt Export?",
                "Do you want to encrypt the exported passwords?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )

            if reply == QMessageBox.Yes:
                result = export_passwords()
            else:
                result = export_passwords(decrypt=True)

            if result["success"]:
                QMessageBox.information(
                    self,
                    "Export Status",
                    result["message"]
                )
            else:
                QMessageBox.critical(self, "Export Error", result["message"])

        except Exception as e:
            QMessageBox.critical(
                self,
                "Export Error",
                f"Failed to export: {str(e)}"
            )


def main():
    """Application entry point."""
    try:
        app = QApplication(sys.argv)

        login_dialog = LoginDialog()

        if login_dialog.exec_() == QDialog.Accepted:
            user = get_current_user()

            if user:
                main_window = MainWindow(user.user.id)
                main_window.show()
                sys.exit(app.exec_())

            else:
                QMessageBox.critical(
                    None,
                    "Authentication Error",
                    "User authentication failed."
                )
                sys.exit(1)

        else:
            sys.exit(0)

    except Exception as e:
        QMessageBox.critical(
            None,
            "Application Error",
            f"An unexpected error occurred: {str(e)}"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
