"""
Moho Motion Sync - High-Speed Multi-Threaded B2 to Encrypted GitHub Mirror
Concurrently mirrors Vaults 01 to 10 into AES-256-GCM encrypted GitHub Releases.
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional, Tuple

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("[!] Error: 'cryptography' is required. Run: pip install cryptography")
    sys.exit(1)

MAGIC_HEADER = b"MMSX"
FORMAT_VERSION = 1
MAX_WORKERS = 8  # 8 parallel cloud-to-cloud transfer streams

KNOWN_VAULTS = {
    "01": {"bucket": "mms-secure-vault-01", "key_id": "005bf0bf426cb820000000001", "app_key": "K005Nzcw0sWUXgwvN2uAtX86PzNveSw"},
    "02": {"bucket": "mms-secure-vault-02", "key_id": "005662c67e5d84d0000000001", "app_key": "K005wqZQEMLweYWFKzJ+Qx+vjaFPvHY"},
    "03": {"bucket": "mms-secure-vault-03", "key_id": "005868f228a70cb0000000001", "app_key": "K005G0wpB9JgNxpc9sLw0FeihGUpGsU"},
    "04": {"bucket": "mms-secure-vault-04", "key_id": "005cba5ae79f02b0000000001", "app_key": "K0059ompgIVdDg7gTjRKo4sZvQT+m4A"},
    "05": {"bucket": "mms-secure-vault-05", "key_id": "0053275942c61440000000001", "app_key": "K005rtHbvjzOWc8mmQZrAzT4JYfoZPM"},
    "06": {"bucket": "mms-secure-vault-06", "key_id": "00514e0dabdf9060000000001", "app_key": "K005ORdbGQU6Ih5nIyLEOP3mXiEtbOo"},
    "07": {"bucket": "mms-secure-vault-07", "key_id": "005668547722b400000000001", "app_key": "K005Rloxwnfwew2TY03qfZHZCJpkj4I"},
    "08": {"bucket": "mms-secure-vault-08", "key_id": "005e967577c6b2d0000000001", "app_key": "K005i6QZX53CU4XtfvL2oaD/CcwYzzE"},
    "09": {"bucket": "mms-secure-vault-09", "key_id": "005f3f8afaf36cb0000000001", "app_key": "K005W6kTXe4glRD/H8YnHYl8gA+ISCc"},
    "10": {"bucket": "mms-secure-vault-10", "key_id": "0056a17e6a16c5b0000000001", "app_key": "K005QdoRzRnY0hqBwjLgTmUOQAj6bHQ"}
}

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
    encoded_name = "/".join(urllib.parse.quote(part) for part in file_name.split("/"))
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
    base_upload_url = upload_url_template.split("{")[0]
    upload_url = f"{base_upload_url}?name={urllib.parse.quote(asset_name)}"
    res = gh_api_request(upload_url, token, method="POST", data=payload_bytes, content_type="application/octet-stream")
    return res.get("browser_download_url", "")

def sanitize_asset_name(remote_path: str) -> str:
    safe = remote_path.replace("/", "_").replace("\\", "_").replace(" ", "_")
    return f"{safe}.bin"

def process_vault(vid: str, vinfo: Dict[str, str], gh_repo: str, gh_token: str, master_key_bytes: bytes):
    b2_bucket_name = vinfo["bucket"]
    release_tag = f"vault-{vid}-mirror"
    print("\n" + "=" * 70)
    print(f"[*] Processing Vault {vid} ({b2_bucket_name}) -> Release: {release_tag}")
    print("=" * 70)

    # 1. Authorize B2
    b2_auth = b2_authorize(vinfo["key_id"], vinfo["app_key"])
    api_url = b2_auth["apiUrl"]
    download_url = b2_auth["downloadUrl"]
    auth_token = b2_auth["authorizationToken"]

    # Retrieve bucketId directly
    bucket_id = b2_auth.get("allowed", {}).get("bucketId")
    if not bucket_id:
        try:
            req_b = urllib.request.Request(
                f"{api_url}/b2api/v2/b2_list_buckets",
                data=json.dumps({"accountId": b2_auth["accountId"]}).encode("utf-8"),
                headers={"Authorization": auth_token, "Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req_b, timeout=30) as resp:
                b_list = json.loads(resp.read().decode("utf-8")).get("buckets", [])
                for b in b_list:
                    if b["bucketName"] == b2_bucket_name:
                        bucket_id = b["bucketId"]
                        break
        except Exception:
            pass

    if not bucket_id:
        print(f"[!] Could not determine bucketId for {b2_bucket_name}. Skipping vault.")
        return

    # 2. List all files
    print(f"[*] Listing all files from bucketId: {bucket_id}...")
    files = b2_list_all_files(api_url, auth_token, bucket_id)
    print(f"[+] Total files in Vault {vid}: {len(files)}")

    # 3. Setup Release on GitHub
    release_info = get_or_create_release(gh_repo, gh_token, release_tag, f"Vault {vid} Encrypted Mirror")
    upload_url_tmpl = release_info["upload_url"]

    # Check already mirrored assets (Paginated fetch up to all assets)
    existing_assets = {}
    rel_id = release_info["id"]
    page = 1
    while True:
        p_url = f"https://api.github.com/repos/{gh_repo}/releases/{rel_id}/assets?per_page=100&page={page}"
        try:
            p_assets = gh_api_request(p_url, gh_token, method="GET")
            if not p_assets:
                break
            for a in p_assets:
                existing_assets[a["name"]] = a["browser_download_url"]
            if len(p_assets) < 100:
                break
            page += 1
        except Exception:
            break

    print(f"[*] Verified existing release assets already mirrored: {len(existing_assets)}")

    # If all files in vault are already mirrored, finish immediately
    unmirrored = [f for f in files if sanitize_asset_name(f["fileName"]) not in existing_assets]
    print(f"[*] Remaining to upload for Vault {vid}: {len(unmirrored)} files (Skipping {len(files) - len(unmirrored)})")

    if not unmirrored:
        print(f"[+] Vault {vid} is already 100% mirrored! Moving to next vault.")
        return

    manifest = {}
    uploaded = 0
    skipped = len(files) - len(unmirrored)
    errors = 0

    # Parallel Worker
    def mirror_worker(item_tuple: Tuple[int, Dict[str, Any]]) -> Tuple[str, str, str, int, str]:
        idx, file_item = item_tuple
        fname = file_item["fileName"]
        asset_name = sanitize_asset_name(fname)

        for attempt in range(3):
            try:
                raw_bytes = b2_download_file(download_url, auth_token, b2_bucket_name, fname)
                encrypted_bin = encrypt_payload(raw_bytes, fname, master_key_bytes)
                dl_url = upload_release_asset(upload_url_tmpl, gh_token, asset_name, encrypted_bin)
                return (fname, asset_name, dl_url, len(raw_bytes), "OK")
            except Exception as e:
                if attempt == 2:
                    return (fname, asset_name, "", 0, f"FAIL: {e}")
                time.sleep(1.0)
        return (fname, asset_name, "", 0, "FAIL: Retries exhausted")

    # Execute with ThreadPoolExecutor
    total_unmirrored = len(unmirrored)
    print(f"[*] Launching {MAX_WORKERS} parallel stream workers for Vault {vid}...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {executor.submit(mirror_worker, (i, f)): f for i, f in enumerate(unmirrored, 1)}
        done_count = 0
        for future in as_completed(future_map):
            done_count += 1
            fname, asset_name, dl_url, sz, status = future.result()
            pct = int((done_count / total_unmirrored) * 100)
            if status == "OK":
                uploaded += 1
                manifest[fname] = {"bin_name": asset_name, "download_url": dl_url, "size": sz}
                print(f"[{done_count}/{total_unmirrored} - {pct}%] Vault {vid} [+] {fname} -> {asset_name}")
            else:
                errors += 1
                print(f"[{done_count}/{total_unmirrored} - {pct}%] Vault {vid} [!] {status} on {fname}")

    # Upload manifest
    try:
        manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
        upload_release_asset(upload_url_tmpl, gh_token, f"vault_{vid}_mirror_manifest.json", manifest_bytes)
    except Exception:
        pass

    print(f"[+] Vault {vid} Complete: Total: {len(files)} | Uploaded: {uploaded} | Skipped: {skipped} | Errors: {errors}")

def main():
    print("=" * 70)
    print("   MOHO MOTION SYNC - MULTI-THREADED (8x) CLOUD MIRROR PIPELINE   ")
    print("=" * 70)

    gh_repo = os.environ.get("GITHUB_REPOSITORY")
    gh_token = os.environ.get("GITHUB_TOKEN")
    master_key_hex = os.environ.get("MMS_MASTER_KEY")
    target_vault = os.environ.get("TARGET_VAULT_ID", "all").strip().lower()

    if not all([gh_repo, gh_token, master_key_hex]):
        print("[!] Error: Missing required environment variables (GITHUB_REPOSITORY, GITHUB_TOKEN, MMS_MASTER_KEY)")
        sys.exit(1)

    master_key_bytes = bytes.fromhex(master_key_hex.strip())
    if len(master_key_bytes) != 32:
        print("[!] Master key must be exactly 32 bytes (64 hex chars).")
        sys.exit(1)

    if target_vault in ["all", ""]:
        vaults_to_run = list(KNOWN_VAULTS.keys())
    elif target_vault in KNOWN_VAULTS:
        vaults_to_run = [target_vault]
    else:
        print(f"[!] Unknown target vault '{target_vault}'. Available: {list(KNOWN_VAULTS.keys())} or 'all'")
        sys.exit(1)

    print(f"[*] Target Repositories: {vaults_to_run}")

    for vid in sorted(vaults_to_run):
        process_vault(vid, KNOWN_VAULTS[vid], gh_repo, gh_token, master_key_bytes)

    print("\n" + "=" * 70)
    print("[+] ALL VAULTS PROCESSED SUCCESSFULLY.")
    print("=" * 70)

if __name__ == "__main__":
    main()
