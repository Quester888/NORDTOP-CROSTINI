import os

# Suspicious patterns to check
FILE_TRAVERSAL = ["os.walk", "glob.glob", "pathlib.rglob"]
FILE_WRITE = ['open(', '"w"', '"wb"']
ENCODING_ENCRYPTION = ["base64.b64encode", "base64.b64decode", "Fernet", "AES", "RSA", "encrypt", "decode"]
KEY_PROMPTS = ["unlock", "decrypt", "password", "key"]

root_path = "/home"  # Change if you want to scan elsewhere
suspicious_files = []

for root, dirs, files in os.walk(root_path):
    for filename in files:
        if filename.endswith(".py"):
            filepath = os.path.join(root, filename)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                
                # Heuristic flags
                flags = []
                if any(pattern in content for pattern in FILE_TRAVERSAL):
                    flags.append("File Traversal")
                if any(pattern in content for pattern in FILE_WRITE):
                    flags.append("File Write")
                if any(pattern in content for pattern in ENCODING_ENCRYPTION):
                    flags.append("Encoding/Encryption")
                if any(pattern.lower() in content.lower() for pattern in KEY_PROMPTS):
                    flags.append("Key Prompt")
                
                # If multiple suspicious behaviors, flag file
                if len(flags) >= 2:
                    suspicious_files.append((filepath, flags))
            
            except (PermissionError, FileNotFoundError):
                continue

# Print results
if suspicious_files:
    print("Suspicious files detected:\n")
    for file, flags in suspicious_files:
        print(f"{file} -> {', '.join(flags)}")
else:
    print("No suspicious files found.")
