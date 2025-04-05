from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QApplication,
    QDialog,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
)

from gui.dialogs.password import UpdatePasswordDialog
from modules.supabase_client import supabase
from modules.utils import decrypt_password, get_user_id


class PasswordTable(QTableWidget):
    """Widget to display stored passwords with View options."""

    def __init__(self, password_list):
        try:
            # Validate input
            if not isinstance(password_list, list):
                raise TypeError("Expected a list of password entries")

            super().__init__(
                len(password_list), 3
            )  # 3 columns: Service, Username, Actions
            self.setHorizontalHeaderLabels(
                ["Service", "Username", "Actions"]
            )  # Set column headers

            # Set table properties
            # Ensure no margin around the table
            self.setContentsMargins(0, 0, 0, 0)

            # Stretch last column
            self.horizontalHeader().setStretchLastSection(True)

            # Adjust column sizes
            self.horizontalHeader().setDefaultSectionSize(150)

            # Hide row headers
            self.verticalHeader().setVisible(False)

            # Populate the table rows
            for row, password_entry in enumerate(password_list):
                self.add_table_row(row, password_entry)

            self.resizeColumnsToContents()
        except Exception as init_error:
            self.handle_table_error(init_error)

    def add_table_row(self, row, password_entry):
        """Add a row to the table and handle errors gracefully."""
        try:
            if not isinstance(password_entry, dict):
                QApplication.processEvents()  # Keep UI responsive
                raise ValueError(f"Invalid entry at row {row}, skipping.")

            service = password_entry.get("service_name", "Unknown")
            username = password_entry.get("username", "Unknown")

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
            view_button.clicked.connect(
                lambda _, r=row: self.handle_view_click(r)
            )
            self.setCellWidget(row, 2, view_button)

        except Exception as row_error:
            self.handle_row_error(row, row_error)

    def handle_row_error(self, row, error):
        """Handle errors for a specific row and show a warning."""
        QMessageBox.warning(
            self,
            "Display Warning",
            f"Failed to display entry at row {row}: {str(error)}",
        )
        # Create empty row with error indication
        self.setItem(row, 0, QTableWidgetItem("Error"))
        self.setItem(row, 1, QTableWidgetItem("Failed to load"))
        self.setCellWidget(row, 2, QPushButton("N/A"))

    def handle_table_error(self, error):
        """Handle errors during table initialization."""
        QMessageBox.critical(
            None,
            "Table Error",
            f"Failed to initialize password table: {str(error)}",
        )
        # Create a minimally functional table
        super().__init__(0, 3)
        self.setHorizontalHeaderLabels(["Service", "Username", "Actions"])

    def handle_view_click(self, row):
        """Handle View button click to fetch and decrypt password."""
        user_id_response = get_user_id()

        if not user_id_response["success"]:
            return user_id_response

        user_id = user_id_response["user_id"]

        if row < 0 or row >= self.rowCount():
            self.show_error_message("Invalid row selection.")
            return

        service = self.item(row, 0).text()
        username = self.item(row, 1).text()

        if service == "Error" and "Failed to load" in username:
            self.show_error_message(
                "This entry failed to load properly and cannot be viewed."
            )
            return

        QApplication.setOverrideCursor(Qt.WaitCursor)

        try:
            # Fetch encrypted password data
            response = self.fetch_password_data(service, username, user_id)

            if not response or not response.data:
                QApplication.restoreOverrideCursor()
                self.show_error_message("No password found for this service.")
                return

            encrypted_password = response.data.get("encrypted_password")
            user_id = response.data.get("user_id")

            if not encrypted_password or not user_id:
                QApplication.restoreOverrideCursor()
                self.show_error_message("Password data is incomplete.")
                return

            # Fetch encryption key data
            key_response = self.fetch_encryption_key(user_id)

            if not key_response or not key_response.data:
                QApplication.restoreOverrideCursor()
                self.show_error_message("Encryption key not found for user.")
                return

            user_key = key_response.data.get("encryption_salt")

            if not user_key:
                QApplication.restoreOverrideCursor()
                self.show_error_message("Invalid encryption key.")
                return

            decrypted_password = decrypt_password(
                encrypted_password,
                user_key
            )

            if not decrypted_password:
                QApplication.restoreOverrideCursor()
                self.show_error_message("Failed to decrypt password.")
                return

            QApplication.restoreOverrideCursor()

            # Open password update dialog
            self.show_update_password_dialog(
                user_id, service, username, decrypted_password, row
            )

        except Exception as e:
            QApplication.restoreOverrideCursor()
            self.show_error_message(f"Failed to retrieve password: {str(e)}")

    def fetch_password_data(self, service, username, user_id):
        """Fetch encrypted password data from the database."""
        try:
            return (
                supabase.table("passwords")
                .select("encrypted_password, user_id")
                .eq("user_id", user_id)
                .eq("service_name", service)
                .eq("username", username)
                .single()
                .execute()
            )
        except Exception as e:
            self.show_error_message(
                f"Failed to retrieve password data: {str(e)}"
            )
            return None

    def fetch_encryption_key(self, user_id):
        """Fetch encryption key from the database."""
        try:
            return (
                supabase.table("user_keys")
                .select("encryption_salt")
                .eq("user_id", user_id)
                .single()
                .execute()
            )
        except Exception as e:
            self.show_error_message(
                f"Failed to retrieve encryption key: {str(e)}"
            )
            return None

    def show_error_message(self, message):
        """Show an error message dialog."""
        QMessageBox.critical(self, "Error", message)

    def show_update_password_dialog(
        self, user_id, service, username, decrypted_password, row
    ):
        """Show the update password dialog."""
        try:
            dialog = UpdatePasswordDialog(
                user_id, service, username, decrypted_password, row, self
            )

            if (
                dialog.exec_() == QDialog.Accepted
                and dialog.updated_service
                and dialog.updated_username
            ):
                service_item = QTableWidgetItem(dialog.updated_service)
                username_item = QTableWidgetItem(dialog.updated_username)

                # Make cells non-editable
                service_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                username_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)

                self.setItem(row, 0, service_item)
                self.setItem(row, 1, username_item)
        except Exception as dialog_error:
            self.show_error_message(
                f"Failed to open password dialog: {str(dialog_error)}"
            )
