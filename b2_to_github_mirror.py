"""
Moho Motion Sync - High-Speed Multi-Threaded Sharded Cloud Mirror (v2.3)
Concurrently mirrors Vaults 01 to 10 into AES-256-GCM encrypted GitHub Releases.

Features:
- Smart Streaming Chunker: Automatically slices large pack files (>800MB, e.g. 7GB packs) into 400MB slices.
  Uses HTTP 206 Range requests from B2 to prevent RAM exhaustion and bypass GitHub's 2GB release limit.
- Smart Rate-Limit Auto-Sleep: When GitHub's 5,000 requests/hr quota is reached, pauses and auto-resumes after reset.
- Automatic Release Sharding (Max 600 files per tag).
- 100% backward compatibility: Preserves and skips existing ~38,000 assets in Vaults 01, 08, 09.
- Dynamic resume and deduplication at both vault and shard level.
"""

import os
import sys
import time
import zlib
import json
import math
import struct
import hashlib
import secrets
import urllib.request
import urllib.error
import urllib.parse
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("[!] Error: 'cryptography' library is required. Run: pip install cryptography")
    sys.exit(1)

MAGIC_HEADER = b"MMSX"
FORMAT_VERSION = 1
MAX_WORKERS_DEFAULT = 8   # 8 parallel streams for normal files
MAX_WORKERS_CHUNKS = 3    # 3 parallel streams for large chunk slices to maintain low RAM (<1.5 GB)
MAX_ASSETS_PER_TAG = 600  # Safe limit well below GitHub's 1,000 cap
CHUNK_THRESHOLD = 800 * 1024 * 1024  # 800 MB: files larger than this are split
CHUNK_SIZE = 400 * 1024 * 1024       # 400 MB slices

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
    with urllib.request.urlopen(req, timeout=300) as resp:
        return resp.read()

def b2_download_file_range(download_url: str, auth_token: str, bucket_name: str, file_name: str, start_byte: int, end_byte: int) -> bytes:
    encoded_name = "/".join(urllib.parse.quote(part) for part in file_name.split("/"))
    url = f"{download_url}/file/{bucket_name}/{encoded_name}"
    req = urllib.request.Request(url, headers={
        "Authorization": auth_token,
        "Range": f"bytes={start_byte}-{end_byte}"
    })
    with urllib.request.urlopen(req, timeout=300) as resp:
        return resp.read()

def encrypt_payload(raw_bytes: bytes, rel_path: str, master_key_bytes: bytes, chunk_meta: Optional[Dict[str, Any]] = None) -> bytes:
    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
    meta = {
        "rel_path": rel_path,
        "size": len(raw_bytes),
        "sha256": sha256_hash,
        "timestamp": int(time.time())
    }
    if chunk_meta:
        meta.update(chunk_meta)
    meta_json = json.dumps(meta).encode("utf-8")
    inner_block = struct.pack(">I", len(meta_json)) + meta_json + raw_bytes
    
    # Use level 4 compression on large chunks for speed and CPU efficiency
    comp_level = 4 if len(raw_bytes) > 50 * 1024 * 1024 else 6
    compressed = zlib.compress(inner_block, level=comp_level)

    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(master_key_bytes)
    ciphertext = aesgcm.encrypt(nonce, compressed, None)
    return MAGIC_HEADER + bytes([FORMAT_VERSION]) + nonce + ciphertext

def gh_api_request(url: str, token: str, method: str = "GET", data: Optional[bytes] = None, content_type: str = "application/json") -> Any:
    req = urllib.request.Request(url, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "MMS-Mirror-Engine/2.3")
    if data is not None:
        req.add_header("Content-Type", content_type)
        req.data = data

    max_attempts = 10
    for attempt in range(max_attempts):
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                res = resp.read()
                return json.loads(res.decode("utf-8")) if res else {}
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="ignore")
            if e.code == 404:
                raise
            
            # Check rate limiting
            if e.code in (403, 429):
                reset_header = e.headers.get("x-ratelimit-reset")
                if "rate limit" in err_body.lower() or reset_header:
                    wait_sec = 60
                    if reset_header:
                        try:
                            wait_sec = max(10, int(reset_header) - int(time.time()) + 15)
                        except Exception:
                            wait_sec = 60
                    print(f"\n[⏳] GitHub API Rate Limit reached (5,000/hr quota). Pausing execution for {wait_sec}s until quota resets...")
                    time.sleep(wait_sec)
                    continue

            print(f"[!] GitHub API HTTP {e.code} on {url}: {err_body}")
            if attempt < max_attempts - 1:
                time.sleep(5)
                continue
            raise

def get_or_create_release(repo: str, token: str, tag: str, title: str) -> Dict[str, Any]:
    url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
    try:
        return gh_api_request(url, token, method="GET")
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise

    # 1. First attempt: gh CLI
    print(f"[*] Creating new release for '{tag}' via GitHub CLI...")
    try:
        env = dict(os.environ)
        env["GH_TOKEN"] = token
        env["GITHUB_TOKEN"] = token
        cmd = ["gh", "release", "create", tag, "--target", "main", "--title", title, "--notes", f"Automated encrypted asset mirror for {tag}."]
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
        if proc.returncode == 0:
            print(f"[+] Release '{tag}' created successfully via gh CLI.")
            time.sleep(2)
            return gh_api_request(url, token, method="GET")
    except Exception as gh_err:
        print(f"[!] gh CLI notice: {gh_err}")

    # 2. Fallback: REST API
    create_url = f"https://api.github.com/repos/{repo}/releases"
    payload = json.dumps({
        "tag_name": tag,
        "target_commitish": "main",
        "name": title,
        "body": f"Automated encrypted asset mirror for {tag}. AES-256-GCM container storage.",
        "draft": False,
        "prerelease": False
    }).encode("utf-8")
    return gh_api_request(create_url, token, method="POST", data=payload)

def get_release_assets_map(repo: str, token: str, tag: str) -> Tuple[Optional[Dict[str, Any]], Dict[str, str]]:
    url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
    try:
        rel = gh_api_request(url, token, method="GET")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None, {}
        raise

    assets_map = {}
    rel_id = rel["id"]
    page = 1
    while True:
        p_url = f"https://api.github.com/repos/{repo}/releases/{rel_id}/assets?per_page=100&page={page}"
        try:
            p_assets = gh_api_request(p_url, token, method="GET")
            if not p_assets:
                break
            for a in p_assets:
                assets_map[a["name"]] = a["browser_download_url"]
                assets_map[normalize_name(a["name"])] = a["browser_download_url"]
            if len(p_assets) < 100:
                break
            page += 1
        except Exception:
            break
    return rel, assets_map

def upload_release_asset(upload_url_template: str, token: str, asset_name: str, payload_bytes: bytes) -> str:
    base_upload_url = upload_url_template.split("{")[0]
    upload_url = f"{base_upload_url}?name={urllib.parse.quote(asset_name)}"
    res = gh_api_request(upload_url, token, method="POST", data=payload_bytes, content_type="application/octet-stream")
    return res.get("browser_download_url", "")

def normalize_name(s: str) -> str:
    return s.replace("(", "").replace(")", "").replace("#", "_").replace("@", "_").replace(" ", "_")

def sanitize_asset_name(remote_path: str) -> str:
    safe = remote_path.replace("/", "_").replace("\\", "_").replace(" ", "_")
    safe = safe.replace("(", "").replace(")", "").replace("#", "_").replace("@", "_")
    return f"{safe}.bin"

def build_upload_tasks(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Expands file list into granular upload tasks.
    Files <= 800MB -> Single task.
    Files > 800MB  -> Multiple 400MB streaming chunk tasks.
    """
    tasks = []
    for f in files:
        fname = f["fileName"]
        fsize = f.get("contentLength", 0)
        base_asset = sanitize_asset_name(fname)

        if fsize <= CHUNK_THRESHOLD:
            tasks.append({
                "type": "single",
                "fileName": fname,
                "asset_name": base_asset,
                "size": fsize
            })
        else:
            total_parts = math.ceil(fsize / CHUNK_SIZE)
            print(f"[*] Large file detected: {fname} ({fsize / (1024*1024):.1f} MB) -> Splitting into {total_parts} streaming chunks.")
            for p_idx in range(1, total_parts + 1):
                start_b = (p_idx - 1) * CHUNK_SIZE
                end_b = min(p_idx * CHUNK_SIZE - 1, fsize - 1)
                chunk_asset = f"{base_asset}.part{p_idx:02d}of{total_parts:02d}.bin"
                tasks.append({
                    "type": "chunk",
                    "fileName": fname,
                    "asset_name": chunk_asset,
                    "part_index": p_idx,
                    "total_parts": total_parts,
                    "start_byte": start_b,
                    "end_byte": end_b,
                    "part_size": end_b - start_b + 1,
                    "total_file_size": fsize
                })
    return tasks

def process_vault(vid: str, vinfo: Dict[str, str], gh_repo: str, gh_token: str, master_key_bytes: bytes):
    b2_bucket_name = vinfo["bucket"]
    print("\n" + "=" * 70)
    print(f"[*] Processing Vault {vid} ({b2_bucket_name})")
    print("=" * 70)

    # 1. Authorize B2
    b2_auth = b2_authorize(vinfo["key_id"], vinfo["app_key"])
    api_url = b2_auth["apiUrl"]
    download_url = b2_auth["downloadUrl"]
    auth_token = b2_auth["authorizationToken"]

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

    # 2. List all files from B2
    print(f"[*] Scanning all files in Vault {vid}...")
    files = b2_list_all_files(api_url, auth_token, bucket_id)
    print(f"[+] Total files discovered in Vault {vid}: {len(files)}")

    if not files:
        print(f"[*] Vault {vid} is empty. Skipping.")
        return

    # 3. Check existing legacy base release `vault-{vid}-mirror`
    base_tag = f"vault-{vid}-mirror"
    base_rel, base_assets = get_release_assets_map(gh_repo, gh_token, base_tag)
    
    all_mirrored_assets = dict(base_assets)
    print(f"[*] Checked base release '{base_tag}': {len(base_assets)} files already mirrored.")

    # Also check any existing shards (vault-{vid}-part02, part03, etc.)
    p_check = 2
    while True:
        check_tag = f"vault-{vid}-part{p_check:02d}"
        s_r, s_a = get_release_assets_map(gh_repo, gh_token, check_tag)
        if not s_r or not s_a:
            break
        print(f"[*] Checked existing shard '{check_tag}': {len(s_a)} assets already mirrored.")
        all_mirrored_assets.update(s_a)
        p_check += 1

    # 4. Build upload tasks (with streaming chunking for large files)
    upload_tasks = build_upload_tasks(files)
    unmirrored_tasks = [t for t in upload_tasks if t["asset_name"] not in all_mirrored_assets and normalize_name(t["asset_name"]) not in all_mirrored_assets]
    print(f"[*] Total upload tasks for Vault {vid}: {len(upload_tasks)} | Remaining unmirrored: {len(unmirrored_tasks)}")

    if not unmirrored_tasks:
        print(f"[+] Vault {vid} is ALREADY 100% MIRRORED! Skipping.")
        return

    # 5. Determine Release Shards
    if len(upload_tasks) <= MAX_ASSETS_PER_TAG and (not base_rel or len(base_assets) < MAX_ASSETS_PER_TAG):
        shards = [(base_tag, unmirrored_tasks)]
    else:
        start_part = p_check
        shards = []
        for i in range(0, len(unmirrored_tasks), MAX_ASSETS_PER_TAG):
            part_tasks = unmirrored_tasks[i:i + MAX_ASSETS_PER_TAG]
            part_num = start_part + len(shards)
            part_tag = f"vault-{vid}-part{part_num:02d}"
            shards.append((part_tag, part_tasks))

    print(f"[*] Sliced remaining tasks into {len(shards)} release shard(s).")

    # 6. Process each shard
    for s_tag, s_tasks in shards:
        print(f"\n---> Shard: {s_tag} ({len(s_tasks)} tasks)")
        s_rel = get_or_create_release(gh_repo, gh_token, s_tag, f"Vault {vid} Mirror - {s_tag}")
        upload_url_tmpl = s_rel["upload_url"]

        _, s_existing = get_release_assets_map(gh_repo, gh_token, s_tag)
        shard_unmirrored = [t for t in s_tasks if t["asset_name"] not in s_existing and normalize_name(t["asset_name"]) not in s_existing]

        if not shard_unmirrored:
            print(f"     [+] Shard {s_tag} already 100% uploaded. Skipping.")
            continue

        # Adjust worker concurrency: if chunk slices exist in shard, limit workers to 3 for low RAM usage
        has_chunks = any(t["type"] == "chunk" for t in shard_unmirrored)
        workers = MAX_WORKERS_CHUNKS if has_chunks else MAX_WORKERS_DEFAULT

        print(f"     [*] Uploading {len(shard_unmirrored)} tasks to {s_tag} with {workers} workers (Chunk mode: {has_chunks})...")

        def task_worker(task_item: Dict[str, Any]) -> Tuple[str, str, str, int, str]:
            fname = task_item["fileName"]
            asset_name = task_item["asset_name"]
            ttype = task_item["type"]

            for attempt in range(5):
                try:
                    if ttype == "single":
                        raw_bytes = b2_download_file(download_url, auth_token, b2_bucket_name, fname)
                        encrypted_bin = encrypt_payload(raw_bytes, fname, master_key_bytes)
                    else:
                        # Stream range for chunk
                        raw_bytes = b2_download_file_range(
                            download_url, auth_token, b2_bucket_name, fname,
                            task_item["start_byte"], task_item["end_byte"]
                        )
                        chunk_meta = {
                            "chunked": True,
                            "part_index": task_item["part_index"],
                            "total_parts": task_item["total_parts"],
                            "start_byte": task_item["start_byte"],
                            "end_byte": task_item["end_byte"],
                            "total_file_size": task_item["total_file_size"],
                            "orig_rel_path": fname
                        }
                        encrypted_bin = encrypt_payload(
                            raw_bytes, f"{fname}__part{task_item['part_index']:02d}",
                            master_key_bytes, chunk_meta
                        )

                    dl_url = upload_release_asset(upload_url_tmpl, gh_token, asset_name, encrypted_bin)
                    return (fname, asset_name, dl_url, len(raw_bytes), "OK")
                except Exception as e:
                    if attempt == 4:
                        return (fname, asset_name, "", 0, f"FAIL: {e}")
                    time.sleep(3.0)
            return (fname, asset_name, "", 0, "FAIL: Retries exhausted")

        manifest = {}
        uploaded = 0
        errors = 0
        total_shard_work = len(shard_unmirrored)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {executor.submit(task_worker, t): t for t in shard_unmirrored}
            done_count = 0
            for future in as_completed(future_map):
                done_count += 1
                fname, asset_name, dl_url, sz, status = future.result()
                pct = int((done_count / total_shard_work) * 100)
                if status == "OK":
                    uploaded += 1
                    manifest[asset_name] = {"file": fname, "download_url": dl_url, "size": sz}
                    print(f"[{done_count}/{total_shard_work} - {pct}%] {s_tag} [+] {fname} -> {asset_name} ({sz / (1024*1024):.1f} MB)")
                else:
                    errors += 1
                    print(f"[{done_count}/{total_shard_work} - {pct}%] {s_tag} [!] {status} on {asset_name}")

        try:
            m_bytes = json.dumps(manifest, indent=2).encode("utf-8")
            upload_release_asset(upload_url_tmpl, gh_token, f"manifest_{s_tag}.json", m_bytes)
        except Exception:
            pass

        print(f"[+] Shard {s_tag} Complete: Uploaded: {uploaded} | Errors: {errors}")

    print(f"\n[+] Vault {vid} Finished Successfully!")

def main():
    print("=" * 70)
    print("   MOHO MOTION SYNC - SHARDED STREAMING CLOUD MIRROR (v2.3)   ")
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
    print("[+] ALL VAULTS PROCESSED AND SHARDED SUCCESSFULLY.")
    print("=" * 70)

if __name__ == "__main__":
    main()
