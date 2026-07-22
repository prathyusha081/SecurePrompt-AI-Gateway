import os
import shutil
from pathlib import Path

# Paths
brain_dir = Path(r"C:\Users\hp\.gemini\antigravity\brain\8aa8a71b-2542-4baf-9d6a-7d16e6c4253b")
target_dir = Path(r"d:\SecurePrompt AI Gateway\secureprompt-ai-gateway\docs\screenshots")

# Create target dir if not exists
target_dir.mkdir(parents=True, exist_ok=True)

# Copy PNG files
copied_files = []
for file in brain_dir.iterdir():
    if file.suffix.lower() == ".png" and "media__" in file.name:
        dest = target_dir / file.name
        shutil.copy(file, dest)
        copied_files.append((file.name, file.stat().st_size))

print(f"Copied {len(copied_files)} screenshots:")
for name, size in copied_files:
    print(f"- {name} ({size / 1024:.1f} KB)")
