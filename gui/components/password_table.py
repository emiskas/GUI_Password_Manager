from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QDialog, QMessageBox, QPushButton, QTableWidget,
                             QTableWidgetItem)

from gui.dialogs.password import UpdatePasswordDialog
from modules.models import Password, SessionLocal

session = SessionLocal()


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
