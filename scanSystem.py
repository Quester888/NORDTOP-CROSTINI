import os
import shutil
import time
from datetime import datetime

# File extensions to scan
TARGET_EXTENSIONS = [".py", ".sh", ".js", ".php", ".rb", ".pl"]

# Suspicious patterns
FILE_TRAVERSAL = ["os.walk", "glob.glob", "pathlib.rglob", "FindFirstFile", "scandir"]
FILE_WRITE = ['open(', '"w"', '"wb"', "fopen", "writeFile", "fs.write"]
ENCODING_ENCRYPTION = ["base64", "Fernet", "AES", "RSA", "encrypt", "decode", "crypto"]
KEY_PROMPTS = ["unlock", "decrypt", "password", "key", "enter key", "restore files"]
NETWORK_ACTIVITY = ["socket", "curl", "wget", "requests", "fetch("]
PROCESS_ACTIVITY = ["subprocess", "os.system", "exec(", "spawn", "fork"]

# System-wide scan path (safe default)
root_path = "/"

# Quarantine folder
quarantine_path = os.path.expanduser("~/malware_quarantine")
os.makedirs(quarantine_path, exist_ok=True)

# Report with timestamp
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
report_path = f"system_scan_REPORT_{timestamp}.txt"
report_lines = []


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


print("\n🔍 Starting full system scan... This may take a while.\n")


for root, dirs, files in os.walk(root_path):
    for filename in files:
        if any(filename.endswith(ext) for ext in TARGET_EXTENSIONS):
            filepath = os.path.join(root, filename)

            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except:
                continue

            flags = []

            # Behavior scanning
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

            # ULTRA HIGH RISK console warning
            if risk_level == "ULTRA HIGH RISK":
                print("\n" + "="*60)
                print("⚠️  ULTRA HIGH RISK FILE DETECTED! ⚠️")
                print(f"File: {filepath}")
                print(f"Flags: {', '.join(flags)}")
                print("Immediate action recommended!")
                print("="*60 + "\n")

            # Auto-quarantine for Ultra High Risk files
            if risk_level == "ULTRA HIGH RISK":
                try:
                    destination = os.path.join(quarantine_path, filename)
                    shutil.copy2(filepath, destination)
                    suggestion += " (File quarantined automatically.)"
                except:
                    suggestion += " (Quarantine failed; check permissions.)"

            # Save result to report
            report_lines.append(f"File: {filepath}")
            report_lines.append(f"Risk Level: {risk_level}")
            report_lines.append(f"Flags: {', '.join(flags)}")
            report_lines.append(f"Suggested Action: {suggestion}")
            report_lines.append("\n" + "-"*70 + "\n")


# Write final report
with open(report_path, "w", encoding="utf-8") as report_file:
    report_file.writelines(line + "\n" for line in report_lines)

print("\n✅ Scan complete.")
print(f"📄 Report saved to: {report_path}")
print(f"📁 Quarantine Folder: {quarantine_path}\n")
