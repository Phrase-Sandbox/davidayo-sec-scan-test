#!/usr/bin/env bash
# Build a single-file ``phrase-sec-scan`` binary for the current platform.
#
# CI calls this from the build-cli.yml matrix on macos-13 / macos-14 /
# ubuntu-latest / windows-latest so each OS/arch produces its own artifact.
# Locally you can run it to spot-check the build before tagging a release.
#
# Output: dist/phrase-sec-scan (Unix) or dist/phrase-sec-scan.exe (Windows).
set -euo pipefail

PY="${PYTHON:-python3}"

"$PY" -m pip install --quiet --upgrade pip
"$PY" -m pip install --quiet pyinstaller
"$PY" -m pip install --quiet -e ".[providers]"

"$PY" -m PyInstaller \
    --onefile \
    --name phrase-sec-scan \
    --hidden-import=security_scanner.skill.local_files \
    --hidden-import=security_scanner.pipeline \
    --hidden-import=security_scanner.shared.claude.client \
    --hidden-import=security_scanner.shared.reports.markdown \
    --collect-submodules security_scanner \
    src/security_scanner/skill/local_cli.py

echo "Built: dist/phrase-sec-scan*"
