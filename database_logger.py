import sqlite3
import os
import time
import csv

class DatabaseLogger:
    """
    Handles logging of scan results to a local SQLite database.
    """

    def __init__(self, db_name="scan_logs.db"):
        self.db_name = db_name
        self._create_table()

    def _create_table(self):
        """
        Creates the logs table if it doesn't already exist.
        """
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT,
                score INTEGER,
                entropy REAL,
                suspicious_strings TEXT,
                reasons TEXT,
                timestamp TEXT
            )
        """)
        conn.commit()
        conn.close()

    def insert_log(self, file_path, score, entropy, found_strings, reasons):
        """
        Inserts a scan result into the database.

        Args:
            file_path (str): Full path of the scanned file.
            score (int): Risk score.
            entropy (float): Entropy value.
            found_strings (list): List of suspicious strings.
            reasons (list): List of reasons the file was flagged.
        """
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO scan_logs (filename, score, entropy, suspicious_strings, reasons, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            os.path.basename(file_path),
            score,
            entropy,
            ", ".join(found_strings),
            " | ".join(reasons),
            time.strftime("%Y-%m-%d %H:%M:%S")
        ))

        conn.commit()
        conn.close()
    def export_to_csv(self, export_path):
     """
    Exports all scan logs to a CSV file.

    Args:
        export_path (str): Path to save the exported CSV.
    Returns:
        tuple: (bool success, str message)
    """
     try:
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scan_logs")
        rows = cursor.fetchall()
        headers = [description[0] for description in cursor.description]

        with open(export_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            writer.writerows(rows)

        conn.close()
        return True, "Logs exported to CSV successfully."
     except Exception as e:
        return False, f"Failed to export logs: {e}"
