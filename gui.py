import os
import math
import threading
import time
from queue import Queue
from collections import Counter
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from database_logger import DatabaseLogger

# === Backend logic classes (same as file_monitor.py) ===

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
            with open(safe_path, 'r', errors='ignore') as f:
                data = f.read()

            if os.path.splitext(safe_path)[1] in self.bad_ext:
                score += 1
                reasons.append("Bad file extension")

            entropy = self.check_entropy(data)
            if entropy > 7.5:
                score += 2
                reasons.append(f"High entropy: {entropy:.2f}")

            found = self.check_strings(data)
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

    def export_report(self, export_path):
        try:
            with open(export_path, 'w') as file:
                file.write("=== Smart File Behavior Analyzer Report ===\n")
                file.write(f"Exported at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                file.write("=" * 45 + "\n\n")
                for entry in self.results:
                    file.write(entry + "\n")
            return True, "Report exported successfully."
        except Exception as e:
            return False, f"Failed to export report: {e}"

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
        self.running = False

    def watch_folder(self):
        seen = set(os.path.abspath(os.path.join(self.folder, f))
                   for f in os.listdir(self.folder)
                   if os.path.isfile(os.path.join(self.folder, f)))
        for path in seen:
            self.queue.put(path)

        while self.running:
            for f in os.listdir(self.folder):
                path = os.path.abspath(os.path.join(self.folder, f))
                if path not in seen and os.path.isfile(path):
                    seen.add(path)
                    self.queue.put(path)
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

# === GUI ===

class FileMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Smart File Behavior Analyzer")
        self.root.geometry("700x500")
        self.root.resizable(False, False)

        self.monitor = None
        self.folder_path = tk.StringVar()

        self.setup_ui()

    def setup_ui(self):
        tk.Label(self.root, text="Watch Folder:").pack(pady=5)
        path_frame = tk.Frame(self.root)
        path_frame.pack()
        tk.Entry(path_frame, textvariable=self.folder_path, width=60).pack(side=tk.LEFT)
        tk.Button(path_frame, text="Browse", command=self.browse_folder).pack(side=tk.LEFT, padx=5)

        control_frame = tk.Frame(self.root)
        control_frame.pack(pady=10)
        tk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring).pack(side=tk.LEFT, padx=10)
        tk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring).pack(side=tk.LEFT)
        tk.Button(control_frame, text="Export Report", command=self.export_report).pack(side=tk.LEFT, padx=10)
        tk.Button(control_frame, text="Export Logs (CSV)", command=self.export_logs_csv).pack(side=tk.LEFT, padx=10)


        tk.Label(self.root, text="Scan Logs:").pack()
        self.log_text = ScrolledText(self.root, width=80, height=20, state='disabled')
        self.log_text.pack(padx=10, pady=5)

        self.status_label = tk.Label(self.root, text="Status: Idle", fg="blue")
        self.status_label.pack(pady=5)

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_path.set(folder)

    def start_monitoring(self):
        folder = self.folder_path.get()
        if not folder or not os.path.isdir(folder):
            messagebox.showerror("Error", "Please select a valid folder.")
            return

        self.monitor = FileMonitor(folder)
        self.monitor.running = True
        self.monitor.start()

        self.status_label.config(text="Status: Monitoring... Scanned files: 0", fg="green")
        threading.Thread(target=self.update_logs, daemon=True).start()

    def stop_monitoring(self):
        if self.monitor:
            self.monitor.running = False
            self.status_label.config(text="Status: Stopped", fg="red")

    def update_logs(self):
        while self.monitor and self.monitor.running:
            logs = self.monitor.report.get_results()
            self.log_text.config(state='normal')
            self.log_text.delete(1.0, tk.END)
            for line in logs:
                self.log_text.insert(tk.END, line + "\n")
            self.log_text.config(state='disabled')

            self.status_label.config(text=f"Status: Monitoring... Scanned files: {len(logs)}", fg="green")
            time.sleep(2)

        if self.monitor and not self.monitor.running:
            self.status_label.config(text="Status: Stopped", fg="red")

    def export_report(self):
        if not self.monitor:
            messagebox.showwarning("Warning", "Monitoring has not been started yet.")
            return

        export_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF Files", "*.pdf")],
            title="Save Report As PDF"
        )
        if export_path:
            success, msg = self.monitor.report.export_report_pdf(export_path)
            if success:
                messagebox.showinfo("Success", msg)
            else:
                messagebox.showerror("Error", msg)
                
    def export_logs_csv(self):
     if not self.monitor or not self.monitor.db_logger:
        messagebox.showwarning("Warning", "Monitoring must be started before exporting logs.")
        return

     export_path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV Files", "*.csv")],
        title="Save Logs As CSV"
    )
    
     if export_path:
        success, msg = self.monitor.db_logger.export_to_csv(export_path)
        if success:
            messagebox.showinfo("Success", msg)
        else:
            messagebox.showerror("Error", msg)



if __name__ == "__main__":
    root = tk.Tk()
    app = FileMonitorGUI(root)
    root.mainloop()
