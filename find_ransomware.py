import os

# Suspicious patterns
FILE_TRAVERSAL = ["os.walk", "glob.glob", "pathlib.rglob"]
FILE_WRITE = ['open(', '"w"', '"wb"']
ENCODING_ENCRYPTION = ["base64.b64encode", "base64.b64decode", "Fernet", "AES", "RSA", "encrypt", "decode"]
KEY_PROMPTS = ["unlock", "decrypt", "password", "key"]

root_path = "/home"  # Adjust this if needed

high_risk = []

for root, dirs, files in os.walk(root_path):
    for filename in files:
        if filename.endswith(".py"):
            filepath = os.path.join(root, filename)

            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                flags = []

                if any(p in content for p in FILE_TRAVERSAL):
                    flags.append("File Traversal")
                if any(p in content for p in FILE_WRITE):
                    flags.append("File Write")
                if any(p in content for p in ENCODING_ENCRYPTION):
                    flags.append("Encoding/Encryption")
                if any(p.lower() in content.lower() for p in KEY_PROMPTS):
                    flags.append("Key Prompt")

                # Only flag files with 3 or more suspicious behaviors
                if len(flags) >= 3:
                    high_risk.append((filepath, flags))

            except (PermissionError, FileNotFoundError):
                continue

# ----- Save Report -----
report_path = "scan_report.txt"
with open(report_path, "w", encoding="utf-8") as report:
    report.write("=== HIGH RISK FILES ===\n\n")
    for file, flags in high_risk:
        report.write(f"{file} -> {', '.join(flags)}\n\n")  # Blank line between entries

print(f"Scan complete. Report saved to: {report_path}")

