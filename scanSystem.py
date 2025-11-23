import os
import shutil
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
from urllib.parse import urlparse

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

    status_area.insert(tk.END, "🔍 Starting system scan...\n")
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

    status_area.insert(tk.END, f"\n✅ System scan complete.\nReport saved to: {report_path}\n")
    status_area.insert(tk.END, f"Quarantine folder: {quarantine_path}\n")

# ------------------ GitHub Safety Checker ------------------ #
def check_github_url():
    url = github_url_entry.get().strip()
    if not url:
        messagebox.showwarning("Input Error", "Please enter a GitHub URL.")
        return

    try:
        path_parts = urlparse(url).path.strip("/").split("/")
        user, repo = path_parts[0], path_parts[1]
    except:
        messagebox.showerror("URL Error", "Invalid GitHub repository URL.")
        return

    status_area.insert(tk.END, f"\n🔍 Checking GitHub repo: {user}/{repo}\n")
    root.update()

    api_url = f"https://api.github.com/repos/{user}/{repo}/contents"
    try:
        response = requests.get(api_url)
        if response.status_code != 200:
            status_area.insert(tk.END, "❌ Could not access repository.\n")
            return

        files = response.json()
        suspicious_files = []

        for f in files:
            name = f.get("name", "")
            if any(name.endswith(ext) for ext in TARGET_EXTENSIONS):
                for keyword in ["encrypt", "decrypt", "key", "ransom"]:
                    if keyword in name.lower():
                        suspicious_files.append(name)

        if suspicious_files:
            status_area.insert(tk.END, f"⚠️ Suspicious files detected: {', '.join(suspicious_files)}\n")
            status_area.insert(tk.END, "Recommendation: Use caution before cloning.\n")
        else:
            status_area.insert(tk.END, "✅ No obvious suspicious files found. Likely safe.\n")

    except Exception as e:
        status_area.insert(tk.END, f"❌ Error checking repo: {str(e)}\n")

# ------------------------- GUI Setup ------------------------- #
root = tk.Tk()
root.title("Crostini Malware + GitHub Safety Tool")
root.geometry("900x650")

frame = ttk.Frame(root, padding=10)
frame.pack(fill=tk.BOTH, expand=True)

# --- System Scan Section ---
scan_button = ttk.Button(frame, text="Start System Scan", command=scan_system)
scan_button.pack(pady=5)

# --- GitHub URL Checker Section ---
github_frame = ttk.LabelFrame(frame, text="GitHub Safety Checker", padding=10)
github_frame.pack(fill=tk.X, pady=10)

github_url_entry = ttk.Entry(github_frame, width=60)
github_url_entry.pack(side=tk.LEFT, padx=5)

check_button = ttk.Button(github_frame, text="Check URL", command=check_github_url)
check_button.pack(side=tk.LEFT, padx=5)

# --- Status Area ---
status_area = scrolledtext.ScrolledText(frame, wrap=tk.WORD)
status_area.pack(fill=tk.BOTH, expand=True, pady=10)

root.mainloop()

