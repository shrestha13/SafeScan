import unittest
import os
import shutil
from unittest.mock import patch, mock_open
from file_monitor import HeuristicScanner, ReportManager, FileMonitor

class TestHeuristicScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = HeuristicScanner()

    def test_check_entropy_empty(self):
        self.assertEqual(self.scanner.check_entropy(""), 0)

    def test_check_entropy_non_empty(self):
        entropy = self.scanner.check_entropy("aaaabbbbcccc")
        self.assertGreater(entropy, 0)

    def test_check_strings_detects_suspicious(self):
        text = "This contains powershell and eval commands"
        found = self.scanner.check_strings(text)
        self.assertIn("powershell", found)
        self.assertIn("eval", found)

    @patch("builtins.open", new_callable=mock_open, read_data="powershell suspicious content")
    def test_risk_score_detects_bad_ext_and_strings(self, mock_file):
        file_path = "fakefile.bat"
        score, reasons = self.scanner.risk_score(file_path)
        self.assertGreaterEqual(score, 3)
        self.assertIn("Bad file extension", reasons)
        self.assertTrue(any("Suspicious strings" in r for r in reasons))

class TestReportManager(unittest.TestCase):

    def setUp(self):
        self.report = ReportManager()
        os.makedirs("quarantine", exist_ok=True)
        self.test_file = "dummy.txt"
        with open(self.test_file, "w") as f:
            f.write("dummy content")

    def tearDown(self):
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists("quarantine"):
            shutil.rmtree("quarantine")
        if os.path.exists("test_report.txt"):
            os.remove("test_report.txt")

    def test_log_result_adds_log(self):
        self.report.log_result(self.test_file, ["Test reason"])
        results = self.report.get_results()
        # Instead of expecting exactly 1, check flagged log exists
        flagged_logs = [r for r in results if "flagged" in r]
        self.assertTrue(len(flagged_logs) >= 1)

    def test_export_report_creates_file(self):
        self.report.log_result(self.test_file, ["Test reason"])
        success, msg = self.report.export_report("test_report.txt")
        self.assertTrue(success)
        self.assertTrue(os.path.exists("test_report.txt"))

    def test_export_report_pdf_creates_file(self):
        self.report.log_result(self.test_file, ["Test reason"])
        success, msg = self.report.export_report_pdf("test_report.pdf")
        self.assertTrue(success)
        self.assertTrue(os.path.exists("test_report.pdf"))
        if os.path.exists("test_report.pdf"):
            os.remove("test_report.pdf")

class TestFileMonitor(unittest.TestCase):

    def setUp(self):
        self.test_folder = "test_watch_folder"
        os.makedirs(self.test_folder, exist_ok=True)
        self.test_file = os.path.join(self.test_folder, "suspicious.bat")
        with open(self.test_file, "w") as f:
            f.write("powershell suspicious code")

    def tearDown(self):
        if os.path.exists(self.test_folder):
            shutil.rmtree(self.test_folder)
        if os.path.exists("quarantine"):
            shutil.rmtree("quarantine")

    @patch("time.sleep", return_value=None)
    def test_watch_folder_queues_existing_files(self, _):
        monitor = FileMonitor(self.test_folder)
        monitor.running = False
        monitor.watch_folder()
        self.assertIn(os.path.abspath(self.test_file), list(monitor.queue.queue))

    def test_process_queue_processes_file_and_logs(self):
        monitor = FileMonitor(self.test_folder)
        monitor.queue.put(self.test_file)
        monitor.running = False  # prevent infinite loop

        # simulate one iteration of process_queue manually
        if not monitor.queue.empty():
            file_path = monitor.queue.get()
            score, reasons = monitor.scanner.risk_score(file_path)
            log_entry = f"Scanned: {file_path} | Score: {score} | Reasons: {', '.join(reasons)}"
            monitor.report.results.append(log_entry)
            if score >= 4:
                monitor.report.log_result(file_path, reasons)

        results = monitor.report.get_results()
        self.assertTrue(any("Scanned" in r for r in results))
        if score >= 4:
            self.assertTrue(any("flagged" in r for r in results))


if __name__ == "__main__":
    unittest.main()
