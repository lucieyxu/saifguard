#!/usr/bin/env python3
"""Fetch and export Google Docs design documents for SAIF security review."""

import argparse
import re
import subprocess
import sys
import urllib.request
from pathlib import Path


def fetch_google_doc_bytes(url: str) -> tuple[bytes | None, str, str]:
    """Fetch a Google Doc (as PDF or plain text) using active gcloud/ADC token or public export link."""
    m = re.search(r"/document/d/([a-zA-Z0-9_-]+)", url)
    if not m:
        return None, "", f"Could not extract Google Doc ID from URL: {url}"
    doc_id = m.group(1)

    token = None
    try:
        proc = subprocess.run(
            ["gcloud", "auth", "print-access-token"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            token = proc.stdout.strip()
    except Exception:
        pass

    export_urls = [
        (f"https://docs.google.com/document/d/{doc_id}/export?format=txt", "text/plain"),
        (f"https://www.googleapis.com/drive/v3/files/{doc_id}/export?mimeType=text/plain", "text/plain"),
        (f"https://docs.google.com/document/d/{doc_id}/export?format=pdf", "application/pdf"),
        (f"https://www.googleapis.com/drive/v3/files/{doc_id}/export?mimeType=application/pdf", "application/pdf"),
    ]

    for exp_url, mime in export_urls:
        try:
            req = urllib.request.Request(exp_url)
            if token:
                req.add_header("Authorization", f"Bearer {token}")
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = resp.read()
                if data and not data.lstrip().startswith(b"<!DOCTYPE html"):
                    return data, mime, ""
        except Exception:
            continue

    return (
        None,
        "",
        f"Unable to download Google Doc '{doc_id}'. Either export it as a PDF into the workspace or run `gcloud auth login --enable-gdrive-access`.",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Export a Google Doc for SAIF architecture audit.")
    parser.add_argument("url", help="Google Docs URL (https://docs.google.com/document/d/<DOC_ID>/...)")
    parser.add_argument("--output", "-o", help="Optional output file path to write the exported content")
    args = parser.parse_args()

    data, mime, err = fetch_google_doc_bytes(args.url)
    if not data:
        print(f"Error: {err}", file=sys.stderr)
        return 1

    if args.output:
        out_path = Path(args.output)
        out_path.write_bytes(data)
        print(f"✓ Exported Google Doc ({mime}) to: {out_path}")
    else:
        if mime == "text/plain":
            print(data.decode("utf-8", errors="replace"))
        else:
            out_path = Path("exported_design_doc.pdf")
            out_path.write_bytes(data)
            print(f"✓ Exported binary PDF to: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
