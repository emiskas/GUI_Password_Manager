import re

from PyQt5.QtWidgets import (QDialog, QLabel, QLineEdit, QMessageBox,
                             QPushButton, QVBoxLayout)

from modules.auth import sign_up


class SignUpDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sign Up")
        self.setGeometry(400, 200, 300, 200)

        layout = QVBoxLayout()

        self.email_label = QLabel("Email:")
        self.email_input = QLineEdit()

        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        self.confirm_password_label = QLabel("Confirm Password:")
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)

        self.signup_button = QPushButton("Sign Up")
        self.signup_button.clicked.connect(self.handle_signup)

        layout.addWidget(self.email_label)
        layout.addWidget(self.email_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.confirm_password_label)
        layout.addWidget(self.confirm_password_input)
        layout.addWidget(self.signup_button)

        self.setLayout(layout)

    def handle_signup(self):
        email = self.email_input.text().strip()
        password = self.password_input.text().strip()
        confirm_password = self.confirm_password_input.text().strip()

        # Email validation
        email_regex = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        if not re.match(email_regex, email):
            QMessageBox.warning(self, "Error", "Invalid email format.")
            return

        if not email or not password:
            QMessageBox.warning(self, "Error", "Email and password cannot be empty.")
            return

        if password != confirm_password:
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            return

        # Strong password check
        if len(password) < 8:
            QMessageBox.warning(
                self, "Error", "Password must be at least 8 characters long."
            )
            return

        if not any(char.isdigit() for char in password):
            QMessageBox.warning(
                self, "Error", "Password must contain at least one number."
            )
            return

        try:
            result = sign_up(email, password)
            if (
                not isinstance(result, dict)
                or "success" not in result
                or "message" not in result
            ):
                raise ValueError("Unexpected response from sign-up function.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Sign-up failed: {str(e)}")
            return

        if result["success"]:
            QMessageBox.information(self, "Success", result["message"])
            self.accept()
        else:
            QMessageBox.warning(self, "Error", result["message"])
            # Clear password fields on failure
            self.password_input.clear()
            self.confirm_password_input.clear()
