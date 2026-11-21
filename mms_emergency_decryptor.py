"""
Moho Motion Sync - Standalone Emergency Disaster Recovery Tool
Decrypts self-contained MMSX (.bin) encrypted containers back into original files.
Zero internet or external services required - 100% offline.
"""

import os
import sys
import zlib
import json
import struct
import hashlib
from pathlib import Path
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("[!] Error: 'cryptography' library is required.")
    print("    Install it via: pip install cryptography")
    sys.exit(1)

MAGIC_HEADER = b"MMSX"
FORMAT_VERSION = 1

def decrypt_container(bin_path: Path, master_key_hex: str, output_base_dir: Path) -> bool:
    try:
        raw_payload = bin_path.read_bytes()
        if len(raw_payload) < 17:
            print(f"[-] Skipped {bin_path.name}: File corrupted or too small.")
            return False

        magic = raw_payload[:4]
        if magic != MAGIC_HEADER:
            print(f"[-] Skipped {bin_path.name}: Invalid magic header ({magic}).")
            return False

        version = raw_payload[4]
        if version != FORMAT_VERSION:
            print(f"[-] Skipped {bin_path.name}: Unsupported container version {version}.")
            return False

        nonce = raw_payload[5:17]
        ciphertext = raw_payload[17:]

        key_bytes = bytes.fromhex(master_key_hex.strip())
        aesgcm = AESGCM(key_bytes)

        # In-memory authentication & decryption
        compressed_inner = aesgcm.decrypt(nonce, ciphertext, None)
        decompressed = zlib.decompress(compressed_inner)

        meta_len = struct.unpack(">I", decompressed[:4])[0]
        meta = json.loads(decompressed[4:4+meta_len].decode("utf-8"))
        original_data = decompressed[4+meta_len:]

        rel_path = meta.get("rel_path", bin_path.stem)
        expected_sha256 = meta.get("sha256")

        if expected_sha256:
            actual_sha256 = hashlib.sha256(original_data).hexdigest()
            if actual_sha256.lower() != expected_sha256.lower():
                print(f"[!] Integrity alert for {bin_path.name}: SHA256 mismatch!")
                return False

        target_file = output_base_dir / rel_path
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_bytes(original_data)

        print(f"[+] Restored: {rel_path} ({len(original_data):,} bytes)")
        return True

    except Exception as e:
        print(f"[-] Decryption failed for {bin_path.name}: {e}")
        return False

def main():
    print("=" * 70)
    print("   MOHO MOTION SYNC - EMERGENCY DISASTER RECOVERY DECRYPTOR   ")
    print("=" * 70)

    # 1. Acquire Master Key
    env_key = os.environ.get("MMS_MASTER_KEY", "").strip()
    if env_key and len(env_key) == 64:
        master_key = env_key
        print("[*] Master key loaded from environment variable.")
    else:
        master_key = input("Enter 64-character Master Key from Bitwarden: ").strip()

    if len(master_key) != 64:
        print("[!] Invalid key length. Master key must be exactly 64 hex characters (32 bytes).")
        sys.exit(1)

    # 2. Acquire target path
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

    # 3. Process files
    bin_files = []
    if target_path.is_file():
        bin_files = [target_path]
    else:
        bin_files = list(target_path.rglob("*.bin"))

    print(f"\n[*] Found {len(bin_files)} .bin files to process.")
    print(f"[*] Restoring to: {output_dir}\n")

    success = 0
    failed = 0

    for idx, f in enumerate(bin_files, 1):
        if decrypt_container(f, master_key, output_dir):
            success += 1
        else:
            failed += 1

    print("\n" + "=" * 70)
    print(f"RECOVERY SUMMARY: Total: {len(bin_files)} | Succeeded: {success} | Failed: {failed}")
    print("=" * 70)

if __name__ == "__main__":
    main()
