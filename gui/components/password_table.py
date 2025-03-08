from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QDialog, QMessageBox, QPushButton, QTableWidget,
                             QTableWidgetItem)

from gui.dialogs.password import UpdatePasswordDialog
from modules.supabase_client import supabase


class PasswordTable(QTableWidget):
    """Widget to display stored passwords with View options."""

    def __init__(self, password_list):
        super().__init__(len(password_list), 3)  # 3 columns: Service, Username, Actions
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
            view_button.clicked.connect(lambda _, r=row: self.handle_view_click(r))
            self.setCellWidget(row, 2, view_button)

        self.resizeColumnsToContents()

    def handle_view_click(self, row):
        """Handle the View button click to fetch password from Supabase."""
        service = self.item(row, 0).text()
        username = self.item(row, 1).text()

        try:
            response = (
                supabase.table("passwords")
                .select("encrypted_password, user_id")
                .eq("service_name", service)
                .eq("username", username)
                .execute()
            )

            if not response.data:
                QMessageBox.warning(
                    self, "Not Found", "No password found for this service."
                )
                return

            encrypted_password = response.data[0]["encrypted_password"]
            user_id = response.data[0]["user_id"]

            dialog = UpdatePasswordDialog(
                user_id, service, username, encrypted_password, row, self
            )

            if dialog.exec_() == QDialog.Accepted:
                self.setItem(row, 0, QTableWidgetItem(dialog.updated_service))
                self.setItem(row, 1, QTableWidgetItem(dialog.updated_username))

        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to retrieve password: {str(e)}"
            )
