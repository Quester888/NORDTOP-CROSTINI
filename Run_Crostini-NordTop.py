import os
import shutil
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from urllib.parse import urlparse, quote
import urllib.request
import re

# Try to import requests, fallback to urllib
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# -------------------- Configuration -------------------- #
TARGET_EXTENSIONS = [".py", ".sh", ".js", ".php", ".rb", ".pl"]
FILE_TRAVERSAL = ["os.walk", "glob.glob", "pathlib.rglob"]
FILE_WRITE = ['open(', '"w"', '"wb"', "fopen", "writeFile", "fs.write"]
ENCODING_ENCRYPTION = ["base64", "Fernet", "AES", "RSA", "encrypt", "decode", "crypto"]
KEY_PROMPTS = ["unlock", "decrypt", "password", "key", "enter key", "restore files"]
NETWORK_ACTIVITY = ["socket", "curl", "wget", "requests", "fetch("]
PROCESS_ACTIVITY = ["subprocess", "os.system", "exec(", "spawn", "fork"]

root_path = "/home"
quarantine_path = os.path.expanduser("~/malware_quarantine")
os.makedirs(quarantine_path, exist_ok=True)
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
report_path = f"system_scan_REPORT_{timestamp}.txt"

# -------------------- Risk Assessment -------------------- #
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

# -------------------- System Scan -------------------- #
def scan_system():
    log_text.delete(1.0, tk.END)
    summary_text.config(state=tk.NORMAL)
    summary_text.delete(1.0, tk.END)
    summary_text.config(state=tk.DISABLED)
    report_lines = []
    log_text.insert(tk.END, "🔍 Starting system scan...\n")
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
                if any(p in content for p in FILE_TRAVERSAL): flags.append("File Traversal")
                if any(p in content for p in FILE_WRITE): flags.append("File Writing")
                if any(p in content for p in ENCODING_ENCRYPTION): flags.append("Encoding/Encryption")
                if any(p.lower() in content.lower() for p in KEY_PROMPTS): flags.append("Ransomware-Style Key Prompt")
                if any(p in content for p in NETWORK_ACTIVITY): flags.append("Network Activity")
                if any(p in content for p in PROCESS_ACTIVITY): flags.append("Process Execution")

                if not flags: continue
                risk_level, suggestion = assess_risk(flags)

                # ULTRA HIGH RISK: auto-quarantine
                if risk_level == "ULTRA HIGH RISK":
                    try:
                        destination = os.path.join(quarantine_path, filename)
                        shutil.copy2(filepath, destination)
                        suggestion += " (File quarantined automatically.)"
                    except:
                        suggestion += " (Quarantine failed; check permissions.)"

                # Log entry
                log_text.insert(tk.END, f"File: {filepath}\nRisk: {risk_level}\nFlags: {', '.join(flags)}\nSuggestion: {suggestion}\n\n")
                log_text.see(tk.END)
                root.update()

                # Color-coded summary
                summary_text.config(state=tk.NORMAL)
                color = {"ULTRA HIGH RISK":"red","High Risk":"orange","Medium Risk":"yellow","Low Risk":"green"}.get(risk_level,"blue")
                summary_text.insert(tk.END, f"{filename}: {risk_level}\n", color)
                summary_text.config(state=tk.DISABLED)

                # Report
                report_lines.append(f"File: {filepath}")
                report_lines.append(f"Risk Level: {risk_level}")
                report_lines.append(f"Flags: {', '.join(flags)}")
                report_lines.append(f"Suggested Action: {suggestion}")
                report_lines.append("\n" + "-"*70 + "\n")

    with open(report_path, "w", encoding="utf-8") as report_file:
        report_file.writelines(line + "\n" for line in report_lines)

    log_text.insert(tk.END, f"\n✅ System scan complete.\nReport saved to: {report_path}\nQuarantine folder: {quarantine_path}\n")

# -------------------- GitHub Scanner -------------------- #
def scan_github_repo(url):
    try:
        path_parts = urlparse(url).path.strip("/").split("/")
        if len(path_parts) < 2: return "Invalid URL"
        user, repo = path_parts[0], path_parts[1]
    except: return "Invalid URL"

    api_url = f"https://api.github.com/repos/{user}/{repo}/contents"
    try:
        if REQUESTS_AVAILABLE:
            response = requests.get(api_url)
            if response.status_code != 200: return f"Failed to access repository: {response.status_code}"
            files = response.json()
        else:
            with urllib.request.urlopen(api_url) as r:
                import json
                files = json.loads(r.read().decode("utf-8"))
    except Exception as e:
        return f"Error: {e}"

    results = []
    for f in files:
        name = f.get("name","")
        download_url = f.get("download_url","")
        if any(name.endswith(ext) for ext in TARGET_EXTENSIONS) and download_url:
            try:
                if REQUESTS_AVAILABLE: raw_file = requests.get(download_url).text
                else:
                    with urllib.request.urlopen(download_url) as rf:
                        raw_file = rf.read().decode("utf-8","ignore")
                flags=[]
                if any(p in raw_file for p in FILE_TRAVERSAL): flags.append("File Traversal")
                if any(p in raw_file for p in FILE_WRITE): flags.append("File Writing")
                if any(p in raw_file for p in ENCODING_ENCRYPTION): flags.append("Encoding/Encryption")
                if any(p.lower() in raw_file.lower() for p in KEY_PROMPTS): flags.append("Key Prompt")
                if any(p in raw_file for p in NETWORK_ACTIVITY): flags.append("Network Activity")
                if any(p in raw_file for p in PROCESS_ACTIVITY): flags.append("Process Execution")
                if flags:
                    risk_level, suggestion = assess_risk(flags)
                    results.append({"file":name,"flags":flags,"risk":risk_level,"suggestion":suggestion})
            except: continue
    return results

def check_github_url():
    url = github_url_entry.get().strip()
    if not url:
        messagebox.showwarning("Input Error","Enter a GitHub URL.")
        return
    log_text.insert(tk.END,f"\n🔍 Checking GitHub repo: {url}\n")
    root.update()
    results = scan_github_repo(url)
    if isinstance(results,str): log_text.insert(tk.END,f"{results}\n"); return
    if not results: log_text.insert(tk.END,"✅ No suspicious files detected.\n"); return
    for r in results:
        log_text.insert(tk.END,f"File: {r['file']}\nRisk: {r['risk']}\nFlags: {', '.join(r['flags'])}\nSuggestion: {r['suggestion']}\n\n")
        log_text.see(tk.END)
        root.update()
        summary_text.config(state=tk.NORMAL)
        color={"ULTRA HIGH RISK":"red","High Risk":"orange","Medium Risk":"yellow","Low Risk":"green"}.get(r['risk'],"blue")
        summary_text.insert(tk.END,f"{r['file']}: {r['risk']}\n",color)
        summary_text.config(state=tk.DISABLED)

# -------------------- Internet Reputation -------------------- #
def check_repo_reputation():
    url = github_url_entry.get().strip()
    if not url:
        messagebox.showwarning("Input Error","Enter a GitHub URL.")
        return
    try: path_parts=urlparse(url).path.strip("/").split("/"); repo_name=path_parts[1]
    except: repo_name=None
    if not repo_name: log_text.insert(tk.END,"❌ Invalid URL.\n"); return
    log_text.insert(tk.END,f"\n🔍 Checking internet reputation for: {repo_name}\n"); root.update()
    query=quote(f"{repo_name} github security malware safe")
    google_url=f"https://www.google.com/search?q={query}"
    try:
        req=urllib.request.Request(google_url,headers={"User-Agent":"Mozilla/5.0"})
        html=urllib.request.urlopen(req).read().decode("utf-8","ignore")
        snippets=re.findall(r"<span class=\".*?\">(.*?)</span>", html)
        cleaned=[re.sub("<.*?>","",s) for s in snippets]
        relevant=[s for s in cleaned if repo_name.lower() in s.lower() or "malware" in s.lower() or "security" in s.lower() or "safe" in s.lower()]
        if not relevant: log_text.insert(tk.END,"No significant reputation info found.\n"); return
        log_text.insert(tk.END,"🌐 Internet Reputation Summary:\n")
        for line in relevant[:8]: log_text.insert(tk.END,f" • {line.strip()}\n")
        text_blob=" ".join(relevant).lower()
        if "malware" in text_blob or "danger" in text_blob: result="❗ Potentially Dangerous"
        elif "issue" in text_blob or "warning" in text_blob: result="⚠️ Mixed Reputation"
        else: result="👍 Looks Safe"
        log_text.insert(tk.END,f"\nReputation Score: {result}\n{'-'*70}\n")
        log_text.see(tk.END)
    except Exception as e: log_text.insert(tk.END,f"Error fetching Google results: {e}\n")

# -------------------- GUI Setup -------------------- #
root = tk.Tk()
root.title("Crostini Malware + GitHub Safety Tool")
root.geometry("1000x750")
frame = ttk.Frame(root,padding=10)
frame.pack(fill=tk.BOTH, expand=True)

# Buttons
button_frame=ttk.Frame(frame)
button_frame.pack(fill=tk.X)
scan_button=ttk.Button(button_frame,text="Start System Scan",command=scan_system)
scan_button.pack(side=tk.LEFT,padx=5,pady=5)
github_url_entry=ttk.Entry(button_frame,width=70)
github_url_entry.pack(side=tk.LEFT,padx=5)
check_button=ttk.Button(button_frame,text="Check GitHub",command=check_github_url)
check_button.pack(side=tk.LEFT,padx=5)
reputation_button=ttk.Button(button_frame,text="Internet Reputation",command=check_repo_reputation)
reputation_button.pack(side=tk.LEFT,padx=5)

# Split panels
panels_frame=ttk.Frame(frame)
panels_frame.pack(fill=tk.BOTH, expand=True)
log_text=scrolledtext.ScrolledText(panels_frame,wrap=tk.WORD,width=70)
log_text.pack(side=tk.LEFT,fill=tk.BOTH,expand=True)
summary_text=scrolledtext.ScrolledText(panels_frame,wrap=tk.WORD,width=35)
summary_text.pack(side=tk.LEFT,fill=tk.BOTH,expand=False)
summary_text.tag_config("red",foreground="red")
summary_text.tag_config("orange",foreground="orange")
summary_text.tag_config("yellow",foreground="goldenrod")
summary_text.tag_config("green",foreground="green")
summary_text.tag_config("blue",foreground="blue")
summary_text.config(state=tk.DISABLED)

root.mainloop()



