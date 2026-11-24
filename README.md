#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def canonical_record_hash(record: dict[str, Any]) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_records(input_path: Path) -> list[dict[str, Any]]:
    suffix = input_path.suffix.lower()
    if suffix == ".csv":
        with input_path.open("r", encoding="utf-8", newline="") as f:
            return [dict(row) for row in csv.DictReader(f)]
    if suffix in {".jsonl", ".ndjson"}:
        records: list[dict[str, Any]] = []
        for line in input_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
        return records
    raise ValueError(f"Unsupported input format: {input_path.suffix}")


def init_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pipeline_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT NOT NULL,
            ingested_at TEXT NOT NULL,
            record_hash TEXT NOT NULL UNIQUE,
            payload_json TEXT NOT NULL
        );
        """
    )
    conn.commit()
    return conn


def run_pipeline(
    input_path: Path,
    db_path: Path,
    jsonl_out: Path,
    metrics_out: Path,
) -> dict[str, int]:
    batch_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ingested_at = datetime.now(timezone.utc).isoformat()
    raw_records = load_records(input_path)
    conn = init_db(db_path)

    inserted = 0
    duplicates = 0
    normalized_lines: list[str] = []

    try:
        with conn:
            for item in raw_records:
                rec_hash = canonical_record_hash(item)
                envelope = {
                    "batch_id": batch_id,
                    "ingested_at": ingested_at,
                    "record_hash": rec_hash,
                    "data": item,
                }
                cur = conn.execute(
                    """
                    INSERT OR IGNORE INTO pipeline_events
                        (batch_id, ingested_at, record_hash, payload_json)
                    VALUES (?, ?, ?, ?);
                    """,
                    (batch_id, ingested_at, rec_hash, json.dumps(envelope, sort_keys=True)),
                )
                if cur.rowcount == 1:
                    inserted += 1
                    normalized_lines.append(json.dumps(envelope, sort_keys=True))
                else:
                    duplicates += 1
    finally:
        conn.close()

    jsonl_out.parent.mkdir(parents=True, exist_ok=True)
    jsonl_out.write_text(
        "\n".join(normalized_lines) + ("\n" if normalized_lines else ""),
        encoding="utf-8",
    )

    metrics_out.parent.mkdir(parents=True, exist_ok=True)
    metrics_text = (
        "# HELP master_pipeline_records_total Total records processed in batch\n"
        "# TYPE master_pipeline_records_total counter\n"
        f'master_pipeline_records_total{{status="inserted"}} {inserted}\n'
        f'master_pipeline_records_total{{status="duplicate"}} {duplicates}\n'
        "# EOF\n"
    )
    metrics_out.write_text(metrics_text, encoding="utf-8")

    return {
        "total_input": len(raw_records),
        "inserted": inserted,
        "duplicates": duplicates,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic local data pipeline ingester")
    parser.add_argument("--input", type=Path, required=True, help="Input .csv or .jsonl file")
    parser.add_argument("--db", type=Path, default=Path("data/pipeline.sqlite"))
    parser.add_argument("--jsonl-out", type=Path, default=Path("data/normalized.jsonl"))
    parser.add_argument("--metrics-out", type=Path, default=Path("data/metrics.prom"))
    args = parser.parse_args()

    stats = run_pipeline(args.input, args.db, args.jsonl_out, args.metrics_out)
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
Master-Hub/
├── .github/
│   └── workflows/
│       └── master-pipeline-ci.yml
├── .gitleaks.toml
├── .gitignore
├── README.md
├── scripts/
│   ├── bootstrap.sh
│   ├── audit_gpg.sh
│   ├── hash_manifest.py
│   ├── vault_encrypt.py
│   ├── backup_all.sh
│   └── pipeline_ingest.py
├── crates/
│   └── integrity-cli/
│       ├── Cargo.toml
│       └── src/
│           └── main.rs
└── tests/
    └── test_pipeline_and_tools.py
README.md
#!/usr/bin/env python3
import argparse
import hashlib
from pathlib import Path

EXCLUDE_DIRS = {".git", "__pycache__", "target", ".pytest_cache", "backups", "vault", "data"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def generate(root: Path, output: Path) -> None:
    lines = []
    for path in sorted(root.rglob("*")):
        if path.is_dir() or any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        if path.resolve() == output.resolve():
            continue
        rel = path.relative_to(root).as_posix()
        lines.append(f"{sha256_file(path)}  {rel}")
    output.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def verify(root: Path, manifest: Path) -> int:
    mismatches = 0
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, rel = line.split("  ", 1)
        target = root / rel
        if not target.exists() or sha256_file(target) != expected:
            print(f"MISMATCH: {rel}")
            mismatches += 1
    return mismatches


def main() -> None:
    parser = argparse.ArgumentParser(description="SHA-256 manifest generator and verifier")
    sub = parser.add_subparsers(dest="cmd", required=True)

    gen_p = sub.add_parser("generate")
    gen_p.add_argument("--root", type=Path, default=Path("."))
    gen_p.add_argument("--output", type=Path, default=Path("MANIFEST.sha256"))

    ver_p = sub.add_parser("verify")
    ver_p.add_argument("--root", type=Path, default=Path("."))
    ver_p.add_argument("--manifest", type=Path, default=Path("MANIFEST.sha256"))

    args = parser.parse_args()
    if args.cmd == "generate":
        generate(args.root, args.output)
    else:
        bad = verify(args.root, args.manifest)
        raise SystemExit(1 if bad else 0)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
import argparse
import base64
import os
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
ITERATIONS = 480_000


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_file(src: Path, dst: Path, password: str) -> None:
    salt = os.urandom(SALT_SIZE)
    token = Fernet(derive_key(password, salt)).encrypt(src.read_bytes())
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(salt + token)


def decrypt_file(src: Path, dst: Path, password: str) -> None:
    raw = src.read_bytes()
    salt, token = raw[:SALT_SIZE], raw[SALT_SIZE:]
    plain = Fernet(derive_key(password, salt)).decrypt(token)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(plain)


def main() -> None:
    parser = argparse.ArgumentParser(description="Symmetric file encryption/decryption")
    sub = parser.add_subparsers(dest="cmd", required=True)

    enc_p = sub.add_parser("encrypt")
    enc_p.add_argument("src", type=Path)
    enc_p.add_argument("dst", type=Path)

    dec_p = sub.add_parser("decrypt")
    dec_p.add_argument("src", type=Path)
    dec_p.add_argument("dst", type=Path)

    args = parser.parse_args()
    password = os.environ.get("VAULT_PASSPHRASE") or input("Enter vault passphrase: ")
    if args.cmd == "encrypt":
        encrypt_file(args.src, args.dst, password)
    else:
        decrypt_file(args.src, args.dst, password)


if __name__ == "__main__":
    main()
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

tar \
  --exclude='.git' \
  --exclude='target' \
  --exclude='__pycache__' \
  --exclude='node_modules' \
  --exclude='.venv' \
  --exclude='*.enc' \
  -cf "${TAR_FILE}" \
  -C "${SOURCE_DIR}" .

zstd -19 -T0 --rm "${TAR_FILE}" -o "${ZST_FILE}"
sha256sum "${ZST_FILE}" > "${MANIFEST_FILE}"

if [[ "${ENCRYPT_BACKUP:-0}" == "1" ]] && [[ -f "scripts/vault_encrypt.py" ]]; then
  python3 scripts/vault_encrypt.py encrypt "${ZST_FILE}" "${ZST_FILE}.enc"
  sha256sum "${ZST_FILE}.enc" >> "${MANIFEST_FILE}"
  rm -f "${ZST_FILE}"
  echo "Encrypted backup created: ${ZST_FILE}.enc"
else
  echo "Backup created: ${ZST_FILE}"
fi

echo "Manifest created: ${MANIFEST_FILE}"
encrypt.py
[package]
name = "integrity-cli"
version = "0.1.0"
edition = "2021"

[dependencies]
sha2 = "0.10"
walkdir = "2.5"
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

fn hash_file(path: &Path) -> Result<String, std::io::Error> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn scan_dir(root: &Path) -> Result<BTreeMap<String, String>, std::io::Error> {
    let mut map = BTreeMap::new();
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            let path: PathBuf = entry.path().to_path_buf();
            if path.components().any(|c| {
                let s = c.as_os_str();
                s == ".git" || s == "target" || s == "__pycache__" || s == "data"
            }) {
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            map.insert(rel, hash_file(&path)?);
        }
    }
    Ok(map)
}

fn main() {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "scan".to_string());
    let root = PathBuf::from(args.next().unwrap_or_else(|| ".".to_string()));

    match cmd.as_str() {
        "scan" => {
            let entries = scan_dir(&root).expect("failed scanning directory");
            for (rel, digest) in entries {
                println!("{digest}  {rel}");
            }
        }
        "check" => {
            let manifest_path =
                PathBuf::from(args.next().unwrap_or_else(|| "MANIFEST.sha256".to_string()));
            let content = fs::read_to_string(&manifest_path).expect("failed reading manifest");
            let current = scan_dir(&root).expect("failed scanning directory");
            let mut mismatches = 0;
            for line in content.lines() {
                if let Some((expected, rel)) = line.split_once("  ") {
                    match current.get(rel) {
                        Some(actual) if actual == expected => {}
                        _ => {
                            eprintln!("DRIFT: {rel}");
                            mismatches += 1;
                        }
                    }
                }
            }
            if mismatches > 0 {
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("Usage: integrity-cli <scan|check> <dir> [manifest_path]");
            std::process::exit(2);
        }
    }
}
from pathlib import Path

from scripts.hash_manifest import generate, verify
from scripts.pipeline_ingest import run_pipeline
from scripts.vault_encrypt import decrypt_file, encrypt_file


def test_pipeline_dedup_and_outputs(tmp_path: Path) -> None:
    csv_file = tmp_path / "events.csv"
    csv_file.write_text("event_id,status\n1,ok\n1,ok\n2,warn\n", encoding="utf-8")

    db_file = tmp_path / "pipeline.sqlite"
    jsonl_file = tmp_path / "out.jsonl"
    metrics_file = tmp_path / "metrics.prom"

    stats = run_pipeline(csv_file, db_file, jsonl_file, metrics_file)
    assert stats["total_input"] == 3
    assert stats["inserted"] == 2
    assert stats["duplicates"] == 1
    assert db_file.exists()
    assert jsonl_file.exists()
    assert "master_pipeline_records_total" in metrics_file.read_text(encoding="utf-8")


def test_manifest_and_vault_roundtrip(tmp_path: Path) -> None:
    sample = tmp_path / "payload.txt"
    sample.write_text("pipeline-state\n", encoding="utf-8")
    manifest = tmp_path / "MANIFEST.sha256"

    generate(tmp_path, manifest)
    assert verify(tmp_path, manifest) == 0

    enc = tmp_path / "payload.enc"
    dec = tmp_path / "restored.txt"
    encrypt_file(sample, enc, "test-passphrase")
    decrypt_file(enc, dec, "test-passphrase")
    assert dec.read_text(encoding="utf-8") == "pipeline-state\n"
name: Master Pipeline CI

on:
  push:
    branches: [ main ]
  pull_request:

jobs:
  pipeline-and-security:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Gitleaks secret scan
        uses: gitleaks/gitleaks-action@v2

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies & run pytest
        run: |
          python -m pip install --upgrade pip pytest cryptography
          PYTHONPATH=. pytest -v

      - name: Set up Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Build & test integrity-cli
        working-directory: crates/integrity-cli
        run: cargo test --locked || cargo test
#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HISTOGRAM_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)


def canonical_record_hash(record: dict[str, Any]) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_records(input_path: Path) -> list[dict[str, Any]]:
    suffix = input_path.suffix.lower()
    if suffix == ".csv":
        with input_path.open("r", encoding="utf-8", newline="") as f:
            return [dict(row) for row in csv.DictReader(f)]
    if suffix in {".jsonl", ".ndjson"}:
        records: list[dict[str, Any]] = []
        for line in input_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
        return records
    raise ValueError(f"Unsupported input format: {input_path.suffix}")


def to_ocsf_event(
    item: dict[str, Any],
    batch_id: str,
    ingested_at: str,
    epoch_ms: int,
    rec_hash: str,
) -> dict[str, Any]:
    severity_raw = str(item.get("severity", item.get("status", "info"))).lower()
    if severity_raw in {"crit", "critical", "error", "err", "fail", "failed"}:
        severity_id, severity = 4, "High"
    elif severity_raw in {"warn", "warning"}:
        severity_id, severity = 2, "Low"
    else:
        severity_id, severity = 1, "Informational"

    return {
        "class_uid": 6003,
        "class_name": "API Activity",
        "category_uid": 6,
        "category_name": "Application Activity",
        "severity_id": severity_id,
        "severity": severity,
        "time": epoch_ms,
        "metadata": {
            "version": "1.3.0",
            "product": {"name": "Master-Hub", "vendor_name": "Local-First"},
            "batch_id": batch_id,
            "ingested_at": ingested_at,
            "record_hash": rec_hash,
        },
        "observables": [{"name": "record_hash", "type_id": 10, "value": rec_hash}],
        "data": item,
    }


def init_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pipeline_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT NOT NULL,
            ingested_at TEXT NOT NULL,
            record_hash TEXT NOT NULL UNIQUE,
            ocsf_class_uid INTEGER NOT NULL,
            severity_id INTEGER NOT NULL,
            payload_json TEXT NOT NULL
        );
        """
    )
    conn.commit()
    return conn


def format_openmetrics(
    inserted: int,
    duplicates: int,
    duration_sec: float,
) -> str:
    lines = [
        "# HELP master_pipeline_records_total Total records processed in batch",
        "# TYPE master_pipeline_records_total counter",
        f'master_pipeline_records_total{{status="inserted"}} {inserted}',
        f'master_pipeline_records_total{{status="duplicate"}} {duplicates}',
        "# HELP master_pipeline_batch_duration_seconds Batch processing duration in seconds",
        "# TYPE master_pipeline_batch_duration_seconds histogram",
    ]
    for bound in HISTOGRAM_BUCKETS:
        count = 1 if duration_sec <= bound else 0
        lines.append(
            f'master_pipeline_batch_duration_seconds_bucket{{le="{bound}"}} {count}'
        )
    lines.append(f'master_pipeline_batch_duration_seconds_bucket{{le="+Inf"}} 1')
    lines.append(f"master_pipeline_batch_duration_seconds_sum {duration_sec:.6f}")
    lines.append("master_pipeline_batch_duration_seconds_count 1")
    lines.append("# EOF")
    return "\n".join(lines) + "\n"


def run_pipeline(
    input_path: Path,
    db_path: Path,
    jsonl_out: Path,
    metrics_out: Path,
) -> dict[str, Any]:
    start = time.perf_counter()
    now_dt = datetime.now(timezone.utc)
    batch_id = now_dt.strftime("%Y%m%dT%H%M%SZ")
    ingested_at = now_dt.isoformat()
    epoch_ms = int(now_dt.timestamp() * 1000)

    raw_records = load_records(input_path)
    conn = init_db(db_path)

    inserted = 0
    duplicates = 0
    normalized_lines: list[str] = []

    try:
        with conn:
            for item in raw_records:
                rec_hash = canonical_record_hash(item)
                event = to_ocsf_event(item, batch_id, ingested_at, epoch_ms, rec_hash)
                cur = conn.execute(
                    """
                    INSERT OR IGNORE INTO pipeline_events
                        (batch_id, ingested_at, record_hash, ocsf_class_uid, severity_id, payload_json)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (
                        batch_id,
                        ingested_at,
                        rec_hash,
                        event["class_uid"],
                        event["severity_id"],
                        json.dumps(event, sort_keys=True),
                    ),
                )
                if cur.rowcount == 1:
                    inserted += 1
                    normalized_lines.append(json.dumps(event, sort_keys=True))
                else:
                    duplicates += 1
    finally:
        conn.close()

    jsonl_out.parent.mkdir(parents=True, exist_ok=True)
    jsonl_out.write_text(
        "\n".join(normalized_lines) + ("\n" if normalized_lines else ""),
        encoding="utf-8",
    )

    elapsed = time.perf_counter() - start
    metrics_out.parent.mkdir(parents=True, exist_ok=True)
    metrics_out.write_text(
        format_openmetrics(inserted, duplicates, elapsed),
        encoding="utf-8",
    )

    return {
        "total_input": len(raw_records),
        "inserted": inserted,
        "duplicates": duplicates,
        "duration_seconds": round(elapsed, 6),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="OCSF-normalized local data pipeline ingester")
    parser.add_argument("--input", type=Path, required=True, help="Input .csv or .jsonl file")
    parser.add_argument("--db", type=Path, default=Path("data/pipeline.sqlite"))
    parser.add_argument("--jsonl-out", type=Path, default=Path("data/normalized.jsonl"))
    parser.add_argument("--metrics-out", type=Path, default=Path("data/metrics.prom"))
    args = parser.parse_args()

    stats = run_pipeline(args.input, args.db, args.jsonl_out, args.metrics_out)
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
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
