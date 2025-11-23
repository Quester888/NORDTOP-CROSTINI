import os

# Suspicious patterns
FILE_TRAVERSAL = ["os.walk", "glob.glob", "pathlib.rglob"]
FILE_WRITE = ['open(', '"w"', '"wb"']
ENCODING_ENCRYPTION = ["base64.b64encode", "base64.b64decode", "Fernet", "AES", "RSA", "encrypt", "decode"]
KEY_PROMPTS = ["unlock", "decrypt", "password", "key"]

root_path = "/home"  # Adjust this if needed

# Risk buckets
low_risk = []
medium_risk = []
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

                # Skip clean files
                if not flags:
                    continue

                # Risk scoring logic
                score = len(flags)

                if score == 1:
                    low_risk.append((filepath, flags))
                elif score == 2:
                    medium_risk.append((filepath, flags))
                else:  # 3 or 4 flags
                    high_risk.append((filepath, flags))

            except (PermissionError, FileNotFoundError):
                continue

# ----- Save Report -----
report_path = "scan_report.txt"
with open(report_path, "w", encoding="utf-8") as report:

    report.write("=== HIGH RISK FILES ===\n")
    for file, flags in high_risk:
        report.write(f"{file} -> {', '.join(flags)}\n")
    report.write("\n")

    report.write("=== MEDIUM RISK FILES ===\n")
    for file, flags in medium_risk:
        report.write(f"{file} -> {', '.join(flags)}\n")
    report.write("\n")

    report.write("=== LOW RISK FILES ===\n")
    for file, flags in low_risk:
        report.write(f"{file} -> {', '.join(flags)}\n")
    report.write("\n")

print(f"Scan complete. Report saved to: {report_path}")



