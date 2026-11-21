# Moho Motion Sync — Encrypted Cloud Vault Mirror

Automated secondary mirror and disaster recovery storage for Moho Motion Sync assets.

## Architecture
- **Storage:** AES-256-GCM Encrypted Containers (`.bin`)
- **Pipeline:** Automated GitHub Actions Runner (Cloud-to-Cloud Sync from Backblaze B2)
- **CDN:** Fastly Global Edge CDN via GitHub Releases

## Contents
- `.github/workflows/mirror_b2_to_releases.yml`: GitHub Actions automated pipeline
- `b2_to_github_mirror.py`: Core mirror engine
- `mms_emergency_decryptor.py`: Standalone offline disaster recovery decryptor
