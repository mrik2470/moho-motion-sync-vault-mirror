"""
Moho Motion Sync - Cloud-to-Cloud Backblaze B2 to GitHub Releases Mirror Pipeline
Runs in GitHub Actions or Google Colab (Zero local PC bandwidth).
Downloads raw assets from B2, encrypts in-memory with AES-256-GCM, and publishes to GitHub Releases.
"""

import os
import sys
import time
import json
import zlib
import struct
import secrets
import hashlib
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("[!] Error: 'cryptography' is required. Run: pip install cryptography")
    sys.exit(1)

MAGIC_HEADER = b"MMSX"
FORMAT_VERSION = 1

def b2_authorize(key_id: str, app_key: str) -> Dict[str, Any]:
    import base64
    cred = base64.b64encode(f"{key_id}:{app_key}".encode("utf-8")).decode("utf-8")
    req = urllib.request.Request(
        "https://api.backblazeb2.com/b2api/v2/b2_authorize_account",
        headers={"Authorization": f"Basic {cred}"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))

def b2_list_all_files(api_url: str, auth_token: str, bucket_id: str) -> List[Dict[str, Any]]:
    files = []
    start_filename = None
    while True:
        payload = {"bucketId": bucket_id, "maxFileCount": 1000}
        if start_filename:
            payload["startFileName"] = start_filename
        req = urllib.request.Request(
            f"{api_url}/b2api/v2/b2_list_file_names",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": auth_token, "Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for f in data.get("files", []):
                files.append(f)
            start_filename = data.get("nextFileName")
            if not start_filename:
                break
    return files

def b2_download_file(download_url: str, auth_token: str, bucket_name: str, file_name: str) -> bytes:
    encoded_name = urllib.parse.quote(file_name)
    url = f"{download_url}/file/{bucket_name}/{encoded_name}"
    req = urllib.request.Request(url, headers={"Authorization": auth_token})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()

def encrypt_payload(raw_bytes: bytes, rel_path: str, master_key_bytes: bytes) -> bytes:
    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
    meta = {
        "rel_path": rel_path,
        "size": len(raw_bytes),
        "sha256": sha256_hash,
        "timestamp": int(time.time())
    }
    meta_json = json.dumps(meta).encode("utf-8")
    inner_block = struct.pack(">I", len(meta_json)) + meta_json + raw_bytes
    compressed = zlib.compress(inner_block, level=6)

    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(master_key_bytes)
    ciphertext = aesgcm.encrypt(nonce, compressed, None)
    return MAGIC_HEADER + bytes([FORMAT_VERSION]) + nonce + ciphertext

def gh_api_request(url: str, token: str, method: str = "GET", data: Optional[bytes] = None, content_type: str = "application/json") -> Any:
    req = urllib.request.Request(url, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        req.add_header("Content-Type", content_type)
        req.data = data
    with urllib.request.urlopen(req, timeout=60) as resp:
        res = resp.read()
        return json.loads(res.decode("utf-8")) if res else {}

def get_or_create_release(repo: str, token: str, tag: str, title: str) -> Dict[str, Any]:
    url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
    try:
        return gh_api_request(url, token, method="GET")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            create_url = f"https://api.github.com/repos/{repo}/releases"
            payload = json.dumps({
                "tag_name": tag,
                "name": title,
                "body": f"Automated encrypted asset mirror for {tag}. AES-256-GCM container storage.",
                "draft": False,
                "prerelease": False
            }).encode("utf-8")
            return gh_api_request(create_url, token, method="POST", data=payload)
        raise

def upload_release_asset(upload_url_template: str, token: str, asset_name: str, payload_bytes: bytes) -> str:
    # upload_url_template is like "https://uploads.github.com/repos/owner/repo/releases/123/assets{?name,label}"
    base_upload_url = upload_url_template.split("{")[0]
    upload_url = f"{base_upload_url}?name={urllib.parse.quote(asset_name)}"
    res = gh_api_request(upload_url, token, method="POST", data=payload_bytes, content_type="application/octet-stream")
    return res.get("browser_download_url", "")

def sanitize_asset_name(remote_path: str) -> str:
    # GitHub release asset names cannot have slashes or backslashes
    safe = remote_path.replace("/", "_").replace("\\", "_").replace(" ", "_")
    return f"{safe}.bin"

def main():
    print("=" * 70)
    print("   MOHO MOTION SYNC - B2 TO GITHUB RELEASES MIRROR PIPELINE   ")
    print("=" * 70)

    # Config from Environment
    b2_key_id = os.environ.get("B2_KEY_ID")
    b2_app_key = os.environ.get("B2_APP_KEY")
    b2_bucket_name = os.environ.get("B2_BUCKET_NAME", "mms-secure-vault-08")
    b2_vault_id = os.environ.get("B2_VAULT_ID", "08")
    gh_repo = os.environ.get("GITHUB_REPOSITORY") # "owner/repo" in GitHub Actions
    gh_token = os.environ.get("GITHUB_TOKEN")
    master_key_hex = os.environ.get("MMS_MASTER_KEY")
    release_tag = os.environ.get("RELEASE_TAG", f"vault-{b2_vault_id}-mirror")

    if not all([b2_key_id, b2_app_key, gh_repo, gh_token, master_key_hex]):
        print("[!] Error: Missing required environment variables:")
        print("    B2_KEY_ID, B2_APP_KEY, GITHUB_REPOSITORY, GITHUB_TOKEN, MMS_MASTER_KEY")
        sys.exit(1)

    master_key_bytes = bytes.fromhex(master_key_hex.strip())
    if len(master_key_bytes) != 32:
        print("[!] Master key must be exactly 32 bytes (64 hex chars).")
        sys.exit(1)

    print(f"[*] Target GitHub Repo : {gh_repo}")
    print(f"[*] Release Tag        : {release_tag}")
    print(f"[*] Source B2 Bucket   : {b2_bucket_name}")

    # 1. Authorize B2
    print("[*] Connecting to Backblaze B2...")
    b2_auth = b2_authorize(b2_key_id, b2_app_key)
    api_url = b2_auth["apiUrl"]
    download_url = b2_auth["downloadUrl"]
    auth_token = b2_auth["authorizationToken"]

    # Find bucket ID
    b_id = None
    req_b = urllib.request.Request(
        f"{api_url}/b2api/v2/b2_list_buckets",
        data=json.dumps({"accountId": b2_auth["accountId"]}).encode("utf-8"),
        headers={"Authorization": auth_token, "Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req_b, timeout=30) as resp:
        b_list = json.loads(resp.read().decode("utf-8")).get("buckets", [])
        for b in b_list:
            if b["bucketName"] == b2_bucket_name:
                b_id = b["bucketId"]
                break

    if not b_id:
        print(f"[!] Bucket {b2_bucket_name} not found in B2 account.")
        sys.exit(1)

    # 2. List all files in B2
    print(f"[*] Listing all assets in {b2_bucket_name}...")
    files = b2_list_all_files(api_url, auth_token, b_id)
    print(f"[+] Total files discovered in B2: {len(files)}")

    # 3. Setup Release on GitHub
    print(f"[*] Checking GitHub Release: {release_tag}...")
    release_info = get_or_create_release(gh_repo, gh_token, release_tag, f"Vault {b2_vault_id} Encrypted Mirror")
    upload_url_tmpl = release_info["upload_url"]

    # Check existing release assets
    existing_assets = {a["name"]: a["browser_download_url"] for a in release_info.get("assets", [])}
    print(f"[*] Existing release assets already mirrored: {len(existing_assets)}")

    manifest = {}
    uploaded_count = 0
    skipped_count = 0
    error_count = 0

    for idx, f in enumerate(files, 1):
        fname = f["fileName"]
        asset_name = sanitize_asset_name(fname)

        if asset_name in existing_assets:
            manifest[fname] = {
                "bin_name": asset_name,
                "download_url": existing_assets[asset_name],
                "size": f.get("contentLength", 0)
            }
            skipped_count += 1
            continue

        print(f"[{idx}/{len(files)}] Mirroring {fname} -> {asset_name}...")
        try:
            # Download from B2
            raw_bytes = b2_download_file(download_url, auth_token, b2_bucket_name, fname)

            # Encrypt with Master Key
            encrypted_bin = encrypt_payload(raw_bytes, fname, master_key_bytes)

            # Upload to GitHub Release
            dl_url = upload_release_asset(upload_url_tmpl, gh_token, asset_name, encrypted_bin)
            manifest[fname] = {
                "bin_name": asset_name,
                "download_url": dl_url,
                "size": len(raw_bytes)
            }
            uploaded_count += 1
            print(f"    [+] Uploaded to GitHub CDN: {dl_url}")

        except Exception as err:
            print(f"    [!] Failed to mirror {fname}: {err}")
            error_count += 1

    # 4. Upload manifest to release
    print("[*] Generating and uploading vault mirror manifest...")
    manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
    manifest_enc = encrypt_payload(manifest_bytes, f"manifest_{release_tag}.json", master_key_bytes)
    
    # Also save plaintext manifest for fast API routing if desired
    try:
        upload_release_asset(upload_url_tmpl, gh_token, "vault_mirror_manifest.json", manifest_bytes)
    except Exception:
        pass

    print("\n" + "=" * 70)
    print(f"MIRROR SUMMARY: Discovered: {len(files)} | Uploaded: {uploaded_count} | Skipped: {skipped_count} | Errors: {error_count}")
    print("=" * 70)

if __name__ == "__main__":
    main()
