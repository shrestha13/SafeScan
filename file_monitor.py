import os
import math
import threading
import time
from queue import Queue
from collections import Counter
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from database_logger import DatabaseLogger


class HeuristicScanner:
    def __init__(self):
        self.suspicious_strings = ["powershell", "cmd.exe", "eval", "exec"]
        self.bad_ext = [".exe", ".bat", ".js"]


    @staticmethod
    def check_entropy(data):
        if not data:
            return 0
        counter = Counter(data)
        total = len(data)
        entropy = -sum((count / total) * math.log2(count / total) for count in counter.values())
        return entropy

    def check_strings(self, data):
        return [s for s in self.suspicious_strings if s in data]

    def risk_score(self, file_path):
        score = 0
        reasons = []
        try:
            safe_path = os.path.abspath(file_path)
            with open(safe_path, 'rb') as f:  # binary mode, no errors param!
                data = f.read()

            if os.path.splitext(safe_path)[1] in self.bad_ext:
                score += 1
                reasons.append("Bad file extension")

            entropy = self.check_entropy(data)
            if entropy > 7.5:
                score += 2
                reasons.append(f"High entropy: {entropy:.2f}")

            found = self.check_strings(data.decode(errors='ignore'))
            if found:
                score += 2
                reasons.append("Suspicious strings: " + ", ".join(found))

        except Exception as e:
            reasons.append(f"Error scanning: {e}")
        return score, reasons


class ReportManager:
    def __init__(self):
        self.results = []
        os.makedirs("quarantine", exist_ok=True)

    def log_result(self, file_path, reasons):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log = f"[{timestamp}] {file_path} flagged: {' | '.join(reasons)}"
        self.results.append(log)

        try:
            filename = os.path.basename(file_path)
            unique_name = time.strftime("%Y%m%d%H%M%S") + "_" + filename
            quarantine_path = os.path.join("quarantine", unique_name)
            os.rename(file_path, quarantine_path)
        except Exception as e:
            self.results.append(f"Failed to quarantine {file_path}: {e}")

    def get_results(self):
        return self.results

   
    def export_report_pdf(self, export_path):
        try:
            c = canvas.Canvas(export_path, pagesize=letter)
            width, height = letter
            c.setFont("Helvetica-Bold", 14)
            c.drawString(30, height - 40, "=== Smart File Behavior Analyzer Report ===")
            c.setFont("Helvetica", 10)
            c.drawString(30, height - 60, f"Exported at: {time.strftime('%Y-%m-%d %H:%M:%S')}")

            y = height - 80
            c.setFont("Helvetica", 9)
            line_height = 14

            for entry in self.results:
                if y < 50:
                    c.showPage()
                    c.setFont("Helvetica", 9)
                    y = height - 50
                c.drawString(30, y, entry)
                y -= line_height
            c.save()
            return True, "PDF report exported successfully."
        except Exception as e:
            return False, f"Failed to export PDF report: {e}"


class FileMonitor:
    def __init__(self, folder):
        self.folder = folder
        self.queue = Queue()
        self.scanner = HeuristicScanner()
        self.report = ReportManager()
        self.db_logger = DatabaseLogger()
        self.running = False

    def watch_folder(self):
        # Queue existing files on start
        seen = set(os.path.abspath(os.path.join(self.folder, f))
                   for f in os.listdir(self.folder)
                   if os.path.isfile(os.path.join(self.folder, f)))

        for path in seen:
            self.queue.put(path)
        print(f"Initial files queued: {seen}")

        while self.running:
            for f in os.listdir(self.folder):
                path = os.path.abspath(os.path.join(self.folder, f))
                if path not in seen and os.path.isfile(path):
                    seen.add(path)
                    self.queue.put(path)
                    print(f"New file detected and queued: {path}")
            time.sleep(2)

    def process_queue(self): 
     while self.running:
        if not self.queue.empty():
            file_path = self.queue.get()
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    data = f.read()

                score, reasons = self.scanner.risk_score(file_path)
                entropy = self.scanner.check_entropy(data)
                found = self.scanner.check_strings(data)

                # Insert into database
                self.db_logger.insert_log(file_path, score, entropy, found, reasons)

                log_entry = f"Scanned: {file_path} | Score: {score} | Reasons: {', '.join(reasons)}"
                self.report.results.append(log_entry)
                print(log_entry)

                if score >= 4:
                    self.report.log_result(file_path, reasons)

            except Exception as e:
                print(f"Error processing {file_path}: {e}")


    def start(self):
        self.running = True
        threading.Thread(target=self.watch_folder, daemon=True).start()
        threading.Thread(target=self.process_queue, daemon=True).start()


if __name__ == '__main__':
    folder = "./watch_folder"
    os.makedirs(folder, exist_ok=True)
    monitor = FileMonitor(folder)
    monitor.start()
    print("Monitoring started. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.running = False
        print("Monitoring stopped.")
