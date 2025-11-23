import os

# Suspicious patterns
FILE_TRAVERSAL = ["os.walk", "glob.glob", "pathlib.rglob"]
FILE_WRITE = ['open(', '"w"', '"wb"']
ENCODING_ENCRYPTION = ["base64.b64encode", "base64.b64decode", "Fernet", "AES", "RSA", "encrypt", "decode"]
KEY_PROMPTS = ["unlock", "decrypt", "password", "key"]

root_path = "/home"  # Adjust this if needed

high_risk = []
ultra_high_risk = []  # New category

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

                score = len(flags)

                # High risk = 3 suspicious behaviors
                if score == 3:
                    high_risk.append((filepath, flags))

                # ULTRA high risk = all 4 behaviors
                elif score == 4:
                    ultra_high_risk.append((filepath, flags))

            except (PermissionError, FileNotFoundError):
                continue

# ----- Print BIG warnings to console -----
if ultra_high_risk:
    print("\n" + "="*60)
    print("⚠️  WARNING: ULTRA HIGH RISK PYTHON FILES DETECTED  ⚠️")
    print("These files match *all* ransomware-like behaviors!")
    print("="*60 + "\n")

    for file, flags in ultra_high_risk:
        print(f"!!! ULTRA HIGH RISK: {file}")
        print(f"Flags: {', '.join(flags)}\n")

# ----- Save Report -----
report_path = "scan_report.txt"

with open(report_path, "w", encoding="utf-8") as report:
    report.write("=== ULTRA HIGH RISK FILES (4 behaviors) ===\n\n")
    for file, flags in ultra_high_risk:
        report.write(f"{file} -> {', '.join(flags)}\n\n")

    report.write("=== HIGH RISK FILES (3 behaviors) ===\n\n")
    for file, flags in high_risk:
        report.write(f"{file} -> {', '.join(flags)}\n\n")

print(f"\nScan complete. Report saved to: {report_path}")

