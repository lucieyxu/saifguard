#!/usr/bin/env python3
"""Fetch and export Google Docs design documents for SAIF security review."""

import argparse
import os
import re
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path


def _get_ssl_context() -> ssl.SSLContext:
    """Create an SSLContext that falls back to macOS/Linux /etc/ssl/cert.pem when Python lacks root CAs."""
    try:
        ctx = ssl.create_default_context()
        if Path("/etc/ssl/cert.pem").is_file():
            ctx.load_verify_locations(cafile="/etc/ssl/cert.pem")
        return ctx
    except Exception:
        return ssl._create_unverified_context()


def _get_gcloud_session():
    """Return an authenticated googlecloudsdk session (supports mTLS/ECP and auto token refresh) without quota project."""
    try:
        sdk_root = None
        if os.environ.get("CLOUDSDK_HOME"):
            sdk_root = Path(os.environ["CLOUDSDK_HOME"])
        elif shutil.which("gcloud"):
            sdk_root = Path(shutil.which("gcloud")).resolve().parent.parent

        if not sdk_root or not (sdk_root / "lib").is_dir():
            proc = subprocess.run(
                ["gcloud", "info", "--format=value(installation.sdk_root)"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                sdk_root = Path(proc.stdout.strip())

        if sdk_root and (sdk_root / "lib").is_dir():
            lib_str = str(sdk_root / "lib")
            tp_str = str(sdk_root / "lib" / "third_party")
            if lib_str not in sys.path:
                sys.path.insert(0, lib_str)
            if tp_str not in sys.path:
                sys.path.insert(0, tp_str)
            from googlecloudsdk.core.credentials import requests as creds_requests
            from googlecloudsdk.core.credentials import store

            store.LoadIfEnabled()
            return creds_requests.GetSession(enable_resource_quota=False)
    except Exception:
        pass
    return None


def _clean_markdown(data: bytes) -> bytes:
    """Strip inline base64 data:image blobs exported by Google Docs Markdown converter."""
    text = data.decode("utf-8", errors="replace")
    cleaned = re.sub(r"\[[^\]]+\]:\s*<data:image/[^>]+>\r?\n?", "", text)
    return cleaned.encode("utf-8")


def fetch_google_doc_bytes(url: str) -> tuple[bytes | None, str, str]:
    """Fetch a Google Doc (as Markdown, plain text, or PDF) using gcloud session/token or public export link."""
    m = re.search(r"/document/d/([a-zA-Z0-9_-]+)", url)
    if not m:
        return None, "", f"Could not extract Google Doc ID from URL: {url}"
    doc_id = m.group(1)

    last_error = ""

    # 1. Try authenticated googlecloudsdk session first (handles mTLS/ECP client certificates & quota project)
    session = _get_gcloud_session()
    if session is not None:
        drive_hosts = [
            "https://www.mtls.googleapis.com",
            "https://www.googleapis.com",
        ]
        for host in drive_hosts:
            for mime in ("text/markdown", "text/plain", "application/pdf"):
                exp_url = f"{host}/drive/v3/files/{doc_id}/export?mimeType={mime}"
                try:
                    resp = session.get(exp_url, timeout=20)
                    if resp.status_code == 200 and resp.content and not resp.content.lstrip().startswith(b"<!DOCTYPE html"):
                        content = _clean_markdown(resp.content) if mime == "text/markdown" else resp.content
                        return content, mime, ""
                    elif resp.status_code in (401, 403, 404):
                        last_error = f"HTTP {resp.status_code}: {resp.text[:200].strip()}"
                except Exception as exc:
                    last_error = str(exc)

    # 2. Fallback to standard urllib with macOS/Linux CA bundle and gcloud access token
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

    ssl_ctx = _get_ssl_context()
    export_urls = [
        (f"https://docs.google.com/document/d/{doc_id}/export?format=md", "text/markdown"),
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
            try:
                resp_ctx = urllib.request.urlopen(req, timeout=20, context=ssl_ctx)
            except TypeError:
                resp_ctx = urllib.request.urlopen(req, timeout=20)
            with resp_ctx as resp:
                data = resp.read()
                if data and not data.lstrip().startswith(b"<!DOCTYPE html"):
                    content = _clean_markdown(data) if mime == "text/markdown" else data
                    return content, mime, ""
        except urllib.error.HTTPError as he:
            last_error = f"HTTP {he.code} ({he.reason})"
        except Exception as exc:
            last_error = str(exc)

    detail = f" (Last error: {last_error})" if last_error else ""
    return (
        None,
        "",
        f"Unable to download Google Doc '{doc_id}'{detail}. Either export it as a PDF into the workspace or run `gcloud auth login --enable-gdrive-access`.",
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
        if mime in ("text/markdown", "text/plain"):
            print(data.decode("utf-8", errors="replace"))
        else:
            out_path = Path("exported_design_doc.pdf")
            out_path.write_bytes(data)
            print(f"✓ Exported binary PDF to: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

