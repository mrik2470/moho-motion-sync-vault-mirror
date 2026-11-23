"""
Moho Motion Sync - Standalone Emergency Disaster Recovery Tool (v2.3)
Decrypts self-contained MMSX (.bin) encrypted containers back into original files.
Automatically reassembles chunked large pack files (.part01, .part02, etc.) in correct byte order.
Zero internet or external services required - 100% offline.
"""

import os
import sys
import zlib
import json
import struct
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, List

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("[!] Error: 'cryptography' library is required.")
    print("    Install it via: pip install cryptography")
    sys.exit(1)

MAGIC_HEADER = b"MMSX"
FORMAT_VERSION = 1

def decrypt_mmsx_container(container_bytes: bytes, master_key_bytes: bytes) -> tuple[Dict[str, Any], bytes]:
    if len(container_bytes) < 17:
        raise ValueError("File is too small to be a valid MMSX container.")

    magic = container_bytes[:4]
    version = container_bytes[4]

    if magic != MAGIC_HEADER:
        raise ValueError(f"Invalid magic header: {magic!r}. Expected {MAGIC_HEADER!r}.")

    if version != FORMAT_VERSION:
        raise ValueError(f"Unsupported container version: {version}. Expected {FORMAT_VERSION}.")

    nonce = container_bytes[5:17]
    ciphertext = container_bytes[17:]

    aesgcm = AESGCM(master_key_bytes)
    decompressed = zlib.decompress(aesgcm.decrypt(nonce, ciphertext, None))

    if len(decompressed) < 4:
        raise ValueError("Corrupt container payload.")

    meta_len = struct.unpack(">I", decompressed[:4])[0]
    meta_json = decompressed[4:4 + meta_len].decode("utf-8")
    meta = json.loads(meta_json)
    original_data = decompressed[4 + meta_len:]

    return meta, original_data

def process_all_files(bin_files: List[Path], master_key_bytes: bytes, output_base_dir: Path):
    # Group chunked files vs single files
    single_files = []
    chunk_groups = {}  # orig_rel_path -> list of (part_index, bin_path)

    for bp in bin_files:
        try:
            raw = bp.read_bytes()
            meta, data = decrypt_mmsx_container(raw, master_key_bytes)
            if meta.get("chunked"):
                orig_rel = meta.get("orig_rel_path", bp.stem)
                part_idx = meta.get("part_index", 1)
                chunk_groups.setdefault(orig_rel, []).append((part_idx, bp, meta, data))
            else:
                single_files.append((bp, meta, data))
        except Exception as e:
            print(f"[-] Failed to read/decrypt {bp.name}: {e}")

    success = 0
    failed = 0

    # 1. Restore single files
    for bp, meta, data in single_files:
        try:
            rel_path = meta.get("rel_path", bp.stem)
            target = output_base_dir / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            print(f"[+] Restored: {rel_path} ({len(data):,} bytes)")
            success += 1
        except Exception as e:
            print(f"[-] Error writing {bp.name}: {e}")
            failed += 1

    # 2. Reassemble and restore chunked files
    for orig_rel, chunks in chunk_groups.items():
        try:
            chunks.sort(key=lambda x: x[0])  # sort by part_index
            target = output_base_dir / orig_rel
            target.parent.mkdir(parents=True, exist_ok=True)
            
            with open(target, "wb") as out_f:
                total_written = 0
                for part_idx, bp, meta, data in chunks:
                    out_f.write(data)
                    total_written += len(data)
            
            print(f"[+] Reassembled & Restored Large File: {orig_rel} ({total_written:,} bytes across {len(chunks)} chunks)")
            success += 1
        except Exception as e:
            print(f"[-] Error reassembling {orig_rel}: {e}")
            failed += 1

    print(f"\n[✓] Restoration complete: {success} files restored successfully, {failed} failed.")

def main():
    print("=" * 70)
    print("   MOHO MOTION SYNC - EMERGENCY DISASTER RECOVERY DECRYPTOR (v2.3)   ")
    print("=" * 70)

    env_key = os.environ.get("MMS_MASTER_KEY", "").strip()
    if env_key and len(env_key) == 64:
        master_key = env_key
        print("[*] Master key loaded from environment variable.")
    else:
        master_key = input("Enter 64-character Master Key from Bitwarden: ").strip()

    if len(master_key) != 64:
        print("[!] Invalid key length. Master key must be exactly 64 hex characters (32 bytes).")
        sys.exit(1)

    master_key_bytes = bytes.fromhex(master_key)

    if len(sys.argv) > 1:
        target_input = sys.argv[1]
    else:
        target_input = input("Enter path to .bin file or directory of .bin files (or press Enter for current dir): ").strip()

    if not target_input:
        target_input = "."

    target_path = Path(target_input).resolve()
    if not target_path.exists():
        print(f"[!] Target path does not exist: {target_path}")
        sys.exit(1)

    default_out = (target_path.parent / "Restored_Assets") if target_path.is_file() else (target_path / "Restored_Assets")
    out_input = input(f"Enter output restoration directory [default: {default_out}]: ").strip()
    output_dir = Path(out_input).resolve() if out_input else default_out
    output_dir.mkdir(parents=True, exist_ok=True)

    bin_files = [target_path] if target_path.is_file() else list(target_path.rglob("*.bin"))
    print(f"\n[*] Found {len(bin_files)} .bin files to process.")
    print(f"[*] Restoring to: {output_dir}\n")

    process_all_files(bin_files, master_key_bytes, output_dir)

if __name__ == "__main__":
    main()
