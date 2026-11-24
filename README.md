[Unit]
Description=Master-Hub Data Pipeline Ingestion and Backup
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=%h/Master-Hub
Environment=ENCRYPT_BACKUP=1
ExecStart=/bin/bash -c 'set -euo pipefail; if [ -f data/incoming.jsonl ]; then python3 scripts/pipeline_ingest.py --input data/incoming.jsonl; fi; python3 scripts/hash_manifest.py generate --root . --output MANIFEST.sha256; bash scripts/backup_all.sh . "$HOME/backups"'

#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="${1:-.}"
BACKUP_ROOT="${2:-$HOME/backups}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
STAGE_DIR="$(mktemp -d)"
ARCHIVE_BASENAME="backup_${TIMESTAMP}"
TAR_FILE="${STAGE_DIR}/${ARCHIVE_BASENAME}.tar"
ZST_FILE="${BACKUP_ROOT}/${ARCHIVE_BASENAME}.tar.zst"
MANIFEST_FILE="${BACKUP_ROOT}/${ARCHIVE_BASENAME}.sha256"

cleanup() {
  rm -rf "${STAGE_DIR}"
}
trap cleanup EXIT

mkdir -p "${BACKUP_ROOT}"

echo "[1/4] Staging files from '${SOURCE_DIR}' (excluding .git, target, __pycache__, node_modules, .venv)..."
tar \
  --exclude='.git' \
  --exclude='target' \
  --exclude='__pycache__' \
  --exclude='node_modules' \
  --exclude='.venv' \
  --exclude='*.enc' \
  -cf "${TAR_FILE}" \
  -C "${SOURCE_DIR}" .

echo "[2/4] Compressing archive with zstd..."
zstd -19 -T0 --rm "${TAR_FILE}" -o "${ZST_FILE}"

echo "[3/4] Generating SHA-256 checksum manifest..."
sha256sum "${ZST_FILE}" > "${MANIFEST_FILE}"

if [[ "${ENCRYPT_BACKUP:-0}" == "1" ]] && [[ -f "scripts/vault_encrypt.py" ]]; then
  echo "[4/4] Encrypting archive with vault_encrypt.py..."
  python3 scripts/vault_encrypt.py encrypt "${ZST_FILE}" "${ZST_FILE}.enc"
  sha256sum "${ZST_FILE}.enc" >> "${MANIFEST_FILE}"
  rm -f "${ZST_FILE}"
  echo "Backup written: ${ZST_FILE}.enc"
else
  echo "[4/4] Skipping encryption (set ENCRYPT_BACKUP=1 to encrypt). Backup written: ${ZST_FILE}"
fi

echo "Manifest written: ${MANIFEST_FILE}"
Master-Hub/
├── .github/
│   └── workflows/
│       └── master-ci.yml
├── .gitleaks.toml
├── .gitignore
├── README.md
├── scripts/
│   ├── bootstrap.sh
│   ├── audit_gpg.sh
│   ├── hash_manifest.py
│   ├── vault_encrypt.py
│   └── backup_all.sh
├── crates/
│   └── integrity-cli/
│       ├── Cargo.toml
│       └── src/
│           └── main.rs
└── tests/
    └── test_security_tools.py
# Local secrets, keys, and sensitive artifacts
*.env
.env.*
*.pem
*.key
*.p12
*.pfx
*.enc
vault/
secrets/
backups/

# Generated manifests & build artifacts
MANIFEST.sha256
*.sha256
*.tar
*.tar.zst
target/
__pycache__/
*.py[cod]
.pytest_cache/
.ruff_cache/

# OS & editor files
.DS_Store
Thumbs.db
*.swp
title = "Master-Hub Secret Scanning Rules"

[extend]
useDefault = true

[[rules]]
id = "generic-private-key-or-token"
description = "Detect high-entropy private keys or bearer tokens"
regex = '''(?i)(api_key|secret_key|private_key|access_token|auth_token)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{20,}['"]?'''
keywords = ["api_key", "secret_key", "private_key", "access_token", "auth_token"]

[allowlist]
description = "Allow test fixtures and placeholder examples"
paths = [
  '''tests/''',
  '''README\.md$'''
]
Thumbs.db
Robert Edward Evans 
evansrobert517@gmail.com 
evansrobert517@yahoo.com 
adpsnake812@gmail.com
adpsnake7@gmail.com 
name: Master-Hub CI

on:
  push:
    branches: [ main ]
  pull_request:

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Scan for secrets with Gitleaks
        uses: gitleaks/gitleaks-action@v2

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Python test dependencies & run pytest
        run: |
          python -m pip install --upgrade pip pytest cryptography
          pytest -v

      - name: Set up Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Run Rust integrity-cli tests
        working-directory: crates/integrity-cli
        run: cargo test --locked || cargo test
# Master-Hub

Local-first security verification, integrity hashing, symmetric vault encryption, and backup tooling.

## Quick Start

```bash
chmod +x scripts/*.sh scripts/*.py
./scripts/bootstrap.sh

Egret Engine
================================================
Current Version: v3.1.5


Developed by Egret Technology, Egret Engine 3.0 includes a newly built 3D engine and a 2D engine created based on HTML5. With its robust cross-platform operability and commitment to solving the performance and fragmentation problems of HTML5 APP and games, Egret Engine 3.0 will perfectly meet developers’ needs. We appreciate every suggestion and please send it to Egret team if you have any.

Platforms:
--------------------
#### PC
* Chrome
* Safari
* FireFox
* IE9+

#### Mobile Browsers / WebView
* iOS 5.0+
* Android 2.3+
* Windows Phone 8

#### Mobile App
* Android 2.3+
* iOS 7.0+
* Windows Phone 8

3rd Party Library
-------------------------
* Egret Team encapsulated some powerful 3rd party libraries,including Gesture,MD5,Particle,Physics. For more information,you can visit [here](https://github.com/egret-labs/egret-game-library)

Tools
-------------------------
* [Egret Wing](http://www.egret.com/products/wing.html) , Egret IDE.

Document & API
-------------------------
* Visit [here](http://edn.egret.com/en/index.php/article/index/id/485) to get tutorials. 
* Visit [here](http://edn.egret.com/en/index.php/apidoc/egret/) to get API.


Release Notes
--------------------
[Egret 3.1.5 Release Notes 2016-7-25](/docs/en/3.1.5_ReleaseNotes.md)

[Egret 3.1.4 Release Notes 2016-7-11](/docs/en/3.1.4_ReleaseNotes.md)

[Egret 3.1.3 Release Notes 2016-6-27](/docs/en/3.1.3_ReleaseNotes.md)

[Egret 3.1.2 Release Notes 2016-6-13](/docs/en/3.1.2_ReleaseNotes.md)

[Egret 3.1.1 Release Notes 2016-5-30](/docs/en/3.1.1_ReleaseNotes.md)

[Egret 3.1.0 Release Notes 2016-5-16](/docs/en/3.1.0_ReleaseNotes.md)

[Egret 3.0.8 Release Notes 2016-5-3](/docs/en/3.0.8_ReleaseNotes.md)

[Egret 3.0.7 Release Notes 2016-4-18](/docs/en/3.0.7_ReleaseNotes.md)

[Egret 3.0.6 Release Notes 2016-4-5](/docs/en/3.0.6_ReleaseNotes.md)

[Egret 3.0.5 Release Notes 2016-3-21](/docs/en/3.0.5_ReleaseNotes.md)

[Egret 3.0.4 Release Notes 2016-3-7](/docs/en/3.0.4_ReleaseNotes.md)

[Egret 3.0.3 Release Notes 2016-2-21](/docs/en/3.0.3_ReleaseNotes.md)

[Egret 3.0.2 Release Notes 2016-1-25](/docs/en/3.0.2_ReleaseNotes.md)

[Egret 3.0.1 Release Notes 2016-1-11](/docs/en/3.0.1_ReleaseNotes.md)

[Egret 3.0.0 Release Notes 2015-12-25](/docs/en/3.0.0_ReleaseNotes.md)

[Egret 2.5.7 Release Notes 2015-12-11](/docs/en/2.5.7_ReleaseNotes.md)

[Egret 2.5.6 Release Notes 2015-11-27](/docs/en/2.5.6_ReleaseNotes.md)

[Egret 2.5.5 Release Notes 2015-11-13](/docs/en/2.5.5_ReleaseNotes.md)

[Egret 2.5.4 Release Notes 2015-10-30](/docs/en/2.5.4_ReleaseNotes.md)

[Egret 2.5.3 Release Notes 2015-10-23](/docs/en/2.5.3_ReleaseNotes.md)

[Egret 2.5.2 Release Notes 2015-10-16](/docs/en/2.5.2_ReleaseNotes.md)

[Egret 2.5.1 Release Notes 2015-10-10](/docs/en/2.5.1_ReleaseNotes.md)

[Egret 2.5.0 Release Notes 2015-9-25](/docs/en/2.5.0_ReleaseNotes.md)

[Egret 2.4.0 Release Notes 2015-7-31](/docs/en/2.4.0_ReleaseNotes.md)

[Egret 1.7.3 Release Notes 2015-6-4](/docs/en/1.7.3_ReleaseNotes.md)

[Egret 1.7.2 Release Notes 2015-5-21](/docs/en/1.7.2_ReleaseNotes.md)

[Egret 1.7.1 Release Notes 2015-5-8](/docs/en/1.7.1_ReleaseNotes.md)

[Egret 1.7.0 Release Notes 2015-4-24](/docs/en/1.7.0_ReleaseNotes.md)

[Egret 1.6.2 Release Notes 2015-4-10](/docs/en/1.6.2_ReleaseNotes.md)

[Egret 1.6.1 Release Notes 2015-3-27](/docs/en/1.6.1_ReleaseNotes.md)

[Egret 1.6.0 Release Notes 2015-3-20](/docs/en/1.6.0_ReleaseNotes.md)

[Egret 1.5.5 Release Notes 2015-2-28](/docs/en/1.5.5_ReleaseNotes.md)


简介
-------------------

Egret Engine 3.0 包含了白鹭时代研发的遵循HTML5标准的2D引擎及全新打造的[3D引擎](https://github.com/egret-labs/egret-3d)，它解决了HTML5性能问题及碎片化问题，灵活地满足开发者开发2D或3D游戏的需求，并有着极强的跨平台运行能力。


支持平台
--------------------
#### PC
* Chrome
* Safari
* FireFox
* IE9+

#### Mobile Browsers / WebView
* iOS 5.0+
* Android 2.3+
* Windows Phone 8

#### Mobile App
* Android 2.3+
* iOS 7.0+
* Windows Phone 8 ( 已支持，参见[这里](http://edn.egret.com/cn/docs/page/171) ）


文档与教程
-------------------------
* 访问 Egret 的 [文档](http://edn.egret.com/cn/docs/)
* 访问 [这里](http://edn.egret.com/cn/apidoc/) 获取 API 文档
* 访问 [这里](https://github.com/egret-team/egret-examples) 获取示例项目

第三方库
-------------------------
* Egret 团队针对引擎封装维护了一些功能强大的第三方库，MD5，手势，粒子系统，物理系统等。访问[这里](https://github.com/egret-labs/egret-game-library)

工具
-------------------------
* [Egret Wing](http://www.egret.com/products/wing.html) , Egret IDE
* [TS Conversion](http://www.egret.com/products/conversion.html) ,AS3到TS的代码转换工具
* [Res Depot](http://www.egret.com/products/others.html#res-depot) ,RES资源模块配置文件管理工具
* [Texture Merger](http://www.egret.com/products/others.html#egret-texture) ,SpriteSheet工具
* [更多工具](http://www.egret.com/products)



发布说明
--------------------
[Egret 3.1.5 Release Notes 2016-7-25](/docs/cn/3.1.5_ReleaseNotes.md)

[Egret 3.1.4 Release Notes 2016-7-11](/docs/cn/3.1.4_ReleaseNotes.md)

[Egret 3.1.3 Release Notes 2016-6-27](/docs/cn/3.1.3_ReleaseNotes.md)

[Egret 3.1.2 Release Notes 2016-6-13](/docs/cn/3.1.2_ReleaseNotes.md)

[Egret 3.1.1 Release Notes 2016-5-30](/docs/cn/3.1.1_ReleaseNotes.md)

[Egret 3.1.0 Release Notes 2016-5-16](/docs/cn/3.1.0_ReleaseNotes.md)

[Egret 3.0.8 Release Notes 2016-5-3](/docs/cn/3.0.8_ReleaseNotes.md)

[Egret 3.0.7 Release Notes 2016-4-18](/docs/cn/3.0.7_ReleaseNotes.md)

[Egret 3.0.6 Release Notes 2016-4-5](/docs/cn/3.0.6_ReleaseNotes.md)

[Egret 3.0.5 Release Notes 2016-3-21](/docs/cn/3.0.5_ReleaseNotes.md)

[Egret 3.0.4 Release Notes 2016-3-7](/docs/cn/3.0.4_ReleaseNotes.md)

[Egret 3.0.3 Release Notes 2016-2-21](/docs/cn/3.0.3_ReleaseNotes.md)

[Egret 3.0.2 Release Notes 2016-1-25](/docs/cn/3.0.2_ReleaseNotes.md)

[Egret 3.0.1 Release Notes 2016-1-11](/docs/cn/3.0.1_ReleaseNotes.md)

[Egret 3.0.0 Release Notes 2015-12-25](/docs/cn/3.0.0_ReleaseNotes.md)

[Egret 2.5.7 Release Notes 2015-12-11](/docs/cn/2.5.7_ReleaseNotes.md)

[Egret 2.5.6 Release Notes 2015-11-27](/docs/cn/2.5.6_ReleaseNotes.md)

[Egret 2.5.5 Release Notes 2015-11-13](/docs/cn/2.5.5_ReleaseNotes.md)

[Egret 2.5.4 Release Notes 2015-10-30](/docs/cn/2.5.4_ReleaseNotes.md)

[Egret 2.5.3 Release Notes 2015-10-23](/docs/cn/2.5.3_ReleaseNotes.md)

[Egret 2.5.2 Release Notes 2015-10-16](/docs/cn/2.5.2_ReleaseNotes.md)

[Egret 2.5.1 Release Notes 2015-10-10](/docs/cn/2.5.1_ReleaseNotes.md)

[Egret 2.5.0 Release Notes 2015-9-25](/docs/cn/2.5.0_ReleaseNotes.md)

[Egret 2.4.0 Release Notes 2015-7-31](/docs/cn/2.4.0_ReleaseNotes.md)

[Egret 1.7.3 Release Notes 2015-6-4](/docs/cn/1.7.3_ReleaseNotes.md)

[Egret 1.7.2 Release Notes 2015-5-21](/docs/cn/1.7.2_ReleaseNotes.md)

[Egret 1.7.1 Release Notes 2015-5-8](/docs/cn/1.7.1_ReleaseNotes.md)

[Egret 1.7.0 Release Notes 2015-4-24](/docs/cn/1.7.0_ReleaseNotes.md)

[Egret 1.6.2 Release Notes 2015-4-10](/docs/cn/1.6.2_ReleaseNotes.md)

[Egret 1.6.1 Release Notes 2015-3-27](/docs/cn/1.6.1_ReleaseNotes.md)

[Egret 1.6.0 Release Notes 2015-3-13](/docs/cn/1.6.0_ReleaseNotes.md)

[Egret 1.5.5 Release Notes 2015-2-28](/docs/cn/1.5.5_ReleaseNotes.md)

[Egret 1.5.4 Release Notes 2015-2-6](/docs/cn/1.5.4_ReleaseNotes.md)

[Egret 1.5.3 Release Notes 2015-1-23](/docs/cn/1.5.3_ReleaseNotes.md)

[Egret 1.5.2 Release Notes 2015-1-9](/docs/cn/1.5.2_ReleaseNotes.md)

[Egret 1.5.1 Release Notes 2014-12-26](/docs/cn/1.5.1_ReleaseNotes.md)

[Egret 1.5.0 Release Notes 2014-12-12](/docs/cn/1.5.0_ReleaseNotes.md)

[Egret 1.1.4 Release Notes 2014-11-28](/docs/cn/1.1.4_ReleaseNotes.md)

[Egret 1.1.3 Release Notes 2014-11-14](/docs/cn/1.1.3_ReleaseNotes.md)

[Egret 1.1.2 Release Notes 2014-10-31](/docs/cn/1.1.2_ReleaseNotes.md)

[Egret 1.1.1 Release Notes 2014-10-17](/docs/cn/1.1.1_ReleaseNotes.md)

[Egret 1.1.0 Release Notes 2014-9-26](/docs/cn/1.1.0_ReleaseNotes.md)

[Egret 1.0.6 Release Notes 2014-9-12](/docs/cn/1.0.6_ReleaseNotes.md)

[Egret 1.0.5 Release Notes 2014-8-29](/docs/cn/1.0.5_ReleaseNotes.md)

[Egret 1.0.4 Release Notes 2014-8-17](/docs/cn/1.0.4_ReleaseNotes.md)

[Egret 1.0.3 Final Release Notes 2014-8-8](/docs/cn/1.0_Final_ReleaseNotes.md)

[Egret 1.0.2 Release Candidate 2 Release Notes 2014-7-25](/docs/cn/ReleaseCandidate_2_ReleaseNotes.md)

[Egret 1.0.1 Release Candidate 1 Release Notes 2014-7-10](/docs/cn/ReleaseCandidate_ReleaseNotes.md)

[Egret 1.0.0 beta Release Notes 2014-5-30](/docs/cn/PublicBeta_ReleaseNotes.md)

[Egret 0.9.4 Release Notes 2014-5-15](/docs/cn/Prerelease_ReleaseNotes.md)

[Egret 0.9.3  Release Notes 2014-4-30](/docs/cn/Prerelease_ReleaseNotes.md)

[Egret 0.9.2  Release Notes 2014-3-27](/docs/cn/Prerelease_ReleaseNotes.md)

[Egret 0.9.1  Release Notes 2014-3-24](/docs/cn/Prerelease_ReleaseNotes.md)

联系我们
-------------------
* 开发者中心: http://edn.egret.com
* 开发者论坛: http://bbs.egret.com
* 开发者群:
  * 1群：141578440 (2000 members capacity / Full)
  * 2群：397297607 (1000 members capacity / Full)
  * 3群：399919028 (1000 members capacity / Full)
  * 4群：125237513 (1000 members capacity / Full)
  * 5群：481169576 (1000 members capacity / avaliable)
