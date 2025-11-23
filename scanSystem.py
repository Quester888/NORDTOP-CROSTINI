import os
import shutil
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# ------------------------- Configuration ------------------------- #
TARGET_EXTENSIONS = [".py", ".sh", ".js", ".php", ".rb", ".pl"]
FILE_TRAVERSAL = ["os.walk", "glob.glob", "pathlib.rglob"]
FILE_WRITE = ['open(', '"w"', '"wb"', "fopen", "writeFile", "fs.write"]
ENCODING_ENCRYPTION = ["base64", "Fernet", "AES", "RSA", "encrypt", "decode", "crypto"]
KEY_PROMPTS = ["unlock", "decrypt", "password", "key", "enter key", "restore files"]
NETWORK_ACTIVITY = ["socket", "curl", "wget", "requests", "fetch("]
PROCESS_ACTIVITY = ["subprocess", "os.system", "exec(", "spawn", "fork"]

root_path = "/home"  # Safe default for Crostini
quarantine_path = os.path.expanduser("~/malware_quarantine")
os.makedirs(quarantine_path, exist_ok=True)

timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
report_path = f"system_scan_REPORT_{timestamp}.txt"

# ------------------------- Helper Functions ------------------------- #
def assess_risk(flags):
    score = len(flags)
    if score <= 1:
        return "Low Risk", "Likely safe; review manually."
    elif score == 2:
        return "Medium Risk", "Possibly suspicious; inspect the file."
    elif score == 3:
        return "High Risk", "Suspicious behavior; consider quarantining."
    else:
        return "ULTRA HIGH RISK", "Very dangerous; quarantine immediately."

def scan_system():
    status_area.delete(1.0, tk.END)
    report_lines = []

    status_area.insert(tk.END, "🔍 Starting scan...\n")
    root.update()

    for root_dir, dirs, files in os.walk(root_path):
        for filename in files:
            if any(filename.endswith(ext) for ext in TARGET_EXTENSIONS):
                filepath = os.path.join(root_dir, filename)

                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except:
                    continue

                flags = []
                if any(p in content for p in FILE_TRAVERSAL):
                    flags.append("File Traversal")
                if any(p in content for p in FILE_WRITE):
                    flags.append("File Writing")
                if any(p in content for p in ENCODING_ENCRYPTION):
                    flags.append("Encryption/Encoding Behavior")
                if any(p.lower() in content.lower() for p in KEY_PROMPTS):
                    flags.append("Ransomware-Style Key Prompt")
                if any(p in content for p in NETWORK_ACTIVITY):
                    flags.append("Network Activity")
                if any(p in content for p in PROCESS_ACTIVITY):
                    flags.append("Process Execution")

                if not flags:
                    continue

                risk_level, suggestion = assess_risk(flags)

                # ULTRA HIGH RISK: auto-quarantine
                if risk_level == "ULTRA HIGH RISK":
                    try:
                        destination = os.path.join(quarantine_path, filename)
                        shutil.copy2(filepath, destination)
                        suggestion += " (File quarantined automatically.)"
                        status_area.insert(tk.END, f"⚠️ ULTRA HIGH RISK detected: {filepath}\n")
                        status_area.insert(tk.END, f"Flags: {', '.join(flags)}\n\n")
                    except:
                        suggestion += " (Quarantine failed; check permissions.)"

                # Append to report
                report_lines.append(f"File: {filepath}")
                report_lines.append(f"Risk Level: {risk_level}")
                report_lines.append(f"Flags: {', '.join(flags)}")
                report_lines.append(f"Suggested Action: {suggestion}")
                report_lines.append("\n" + "-"*70 + "\n")

                status_area.see(tk.END)
                root.update()

    # Save report
    with open(report_path, "w", encoding="utf-8") as report_file:
        report_file.writelines(line + "\n" for line in report_lines)

    status_area.insert(tk.END, f"\n✅ Scan complete.\nReport saved to: {report_path}\n")
    status_area.insert(tk.END, f"Quarantine folder: {quarantine_path}\n")

# ------------------------- GUI Setup ------------------------- #
root = tk.Tk()
root.title("Crostini Malware Scanner")

root.geometry("800x600")

frame = ttk.Frame(root, padding=10)
frame.pack(fill=tk.BOTH, expand=True)

scan_button = ttk.Button(frame, text="Start Scan", command=scan_system)
scan_button.pack(pady=5)

status_area = scrolledtext.ScrolledText(frame, wrap=tk.WORD)
status_area.pack(fill=tk.BOTH, expand=True, pady=10)

root.mainloop()
