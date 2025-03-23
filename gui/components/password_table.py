from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QApplication, QDialog, QMessageBox, QPushButton,
                             QTableWidget, QTableWidgetItem)

from gui.dialogs.password import UpdatePasswordDialog
from modules.supabase_client import supabase
from modules.utils import decrypt_password


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
            self.setContentsMargins(0, 0, 0, 0)  # Ensure no margin around the table
            self.horizontalHeader().setStretchLastSection(True)  # Stretch last column
            self.horizontalHeader().setDefaultSectionSize(150)  # Adjust column sizes
            self.verticalHeader().setVisible(False)  # Hide row headers

            # Populate the table rows
            for row, password_entry in enumerate(password_list):
                try:
                    if not isinstance(password_entry, dict):
                        QApplication.processEvents()  # Keep UI responsive
                        continue  # Skip invalid entries

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
                    QMessageBox.warning(
                        self,
                        "Display Warning",
                        f"Failed to display entry at row {row}: {str(row_error)}",
                    )
                    # Create empty row with error indication
                    self.setItem(row, 0, QTableWidgetItem("Error"))
                    self.setItem(row, 1, QTableWidgetItem("Failed to load"))
                    self.setCellWidget(row, 2, QPushButton("N/A"))

            self.resizeColumnsToContents()
        except Exception as init_error:
            QMessageBox.critical(
                None,
                "Table Error",
                f"Failed to initialize password table: {str(init_error)}",
            )
            # Create a minimally functional table
            super().__init__(0, 3)
            self.setHorizontalHeaderLabels(["Service", "Username", "Actions"])

    def handle_view_click(self, row):
        """Handle the View button click to fetch and decrypt password from Supabase."""
        # Check row bounds
        if row < 0 or row >= self.rowCount():
            QMessageBox.warning(self, "Error", "Invalid row selection.")
            return

        # Validate cell items exist
        if not self.item(row, 0) or not self.item(row, 1):
            QMessageBox.warning(self, "Error", "Row data is incomplete.")
            return

        service = self.item(row, 0).text()
        username = self.item(row, 1).text()

        # Check if this is an error row
        if service == "Error" and "Failed to load" in username:
            QMessageBox.warning(
                self,
                "Error",
                "This entry failed to load properly and cannot be viewed.",
            )
            return

        QApplication.setOverrideCursor(Qt.WaitCursor)  # Show waiting cursor

        try:
            # First database call - get password
            try:
                response = (
                    supabase.table("passwords")
                    .select("encrypted_password, user_id")
                    .eq("service_name", service)
                    .eq("username", username)
                    .single()
                    .execute()
                )
            except TimeoutError:
                QApplication.restoreOverrideCursor()
                QMessageBox.critical(
                    self,
                    "Connection Error",
                    "Database query timed out. Check your connection and try again.",
                )
                return
            except supabase.PostgrestError as db_error:
                QApplication.restoreOverrideCursor()
                QMessageBox.critical(
                    self, "Database Error", f"Database query failed: {str(db_error)}"
                )
                return
            except Exception as query_error:
                QApplication.restoreOverrideCursor()
                QMessageBox.critical(
                    self,
                    "Query Error",
                    f"Failed to retrieve password data: {str(query_error)}",
                )
                return

            if not response or not response.data:
                QApplication.restoreOverrideCursor()
                QMessageBox.warning(
                    self, "Not Found", "No password found for this service."
                )
                return

            encrypted_password = response.data.get("encrypted_password")
            user_id = response.data.get("user_id")

            if not encrypted_password or not user_id:
                QApplication.restoreOverrideCursor()
                QMessageBox.critical(self, "Data Error", "Password data is incomplete.")
                return

            # Second database call - get encryption key
            try:
                key_response = (
                    supabase.table("user_keys")
                    .select("encryption_salt")
                    .eq("user_id", user_id)
                    .single()
                    .execute()
                )
            except TimeoutError:
                QApplication.restoreOverrideCursor()
                QMessageBox.critical(
                    self,
                    "Connection Error",
                    "Key retrieval timed out. Check your connection and try again.",
                )
                return
            except supabase.PostgrestError as db_error:
                QApplication.restoreOverrideCursor()
                QMessageBox.critical(
                    self,
                    "Database Error",
                    f"Failed to retrieve encryption key: {str(db_error)}",
                )
                return
            except Exception as key_error:
                QApplication.restoreOverrideCursor()
                QMessageBox.critical(
                    self,
                    "Key Error",
                    f"Failed to retrieve encryption key: {str(key_error)}",
                )
                return

            if not key_response or not key_response.data:
                QApplication.restoreOverrideCursor()
                QMessageBox.critical(
                    self, "Error", "Encryption key not found for user."
                )
                return

            user_key = key_response.data.get("encryption_salt")

            if not user_key:
                QApplication.restoreOverrideCursor()
                QMessageBox.critical(self, "Key Error", "Invalid encryption key.")
                return

            # Decrypt password
            try:
                decrypted_password = decrypt_password(encrypted_password, user_key)

                if not decrypted_password:
                    QApplication.restoreOverrideCursor()
                    QMessageBox.critical(
                        self, "Decryption Error", "Failed to decrypt password."
                    )
                    return
            except Exception as decrypt_error:
                QApplication.restoreOverrideCursor()
                QMessageBox.critical(
                    self,
                    "Decryption Error",
                    f"Failed to decrypt password: {str(decrypt_error)}",
                )
                return

            QApplication.restoreOverrideCursor()  # Restore cursor

            # Create and show dialog
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
                QMessageBox.critical(
                    self,
                    "Dialog Error",
                    f"Failed to open password dialog: {str(dialog_error)}",
                )

        except Exception as e:
            QApplication.restoreOverrideCursor()  # Ensure cursor is restored
            QMessageBox.critical(
                self, "Error", f"Failed to retrieve password: {str(e)}"
            )
