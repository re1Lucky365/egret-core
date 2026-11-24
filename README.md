Master-Hub/
├── .github/
│   └── workflows/
│       └── master-ci.yml
├── .gitleaks.toml
├── .gitignore
├── scripts/
│   ├── bootstrap.sh
│   ├── audit_gpg.sh
│   ├── hash_manifest.py
│   └── vault_encrypt.py
├── crates/
│   └── integrity-cli/
│       ├── Cargo.toml
│       └── src/main.rs
├── tests/
│   └── test_security_tools.py
└── README.md
audit_gpg.sh
Master-Hub/
├── .github/
│   └── workflows/
│       └── master-ci.yml
├── .gitleaks.toml
├── .gitignore
├── scripts/
│   ├── bootstrap.sh
│   ├── audit_gpg.sh
│   ├── hash_manifest.py
│   └── vault_encrypt.py
├── crates/
│   └── integrity-cli/
│       ├── Cargo.toml
│       └── src/main.rs
├── tests/
│   └── test_security_tools.py
└── README.md
master-ci.yml
bootstrap.sh
README.md#!/usr/bin/env python3
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
    dst.write_bytes(salt + token)


def decrypt_file(src: Path, dst: Path, password: str) -> None:
    raw = src.read_bytes()
    salt, token = raw[:SALT_SIZE], raw[SALT_SIZE:]
    plain = Fernet(derive_key(password, salt)).decrypt(token)
    dst.write_bytes(plain)


def main() -> None:
    parser = argparse.ArgumentParser(description="Local symmetric file encrypt/decrypt")
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
            if path.components().any(|c| c.as_os_str() == ".git" || c.as_os_str() == "target") {
                continue;
            }
            let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().replace('\\', "/");
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
            let manifest_path = PathBuf::from(args.next().unwrap_or_else(|| "MANIFEST.sha256".to_string()));
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
from scripts.vault_encrypt import decrypt_file, encrypt_file


def test_manifest_generate_and_verify(tmp_path: Path) -> None:
    sample = tmp_path / "notes.txt"
    sample.write_text("integrity-check\n", encoding="utf-8")
    manifest = tmp_path / "MANIFEST.sha256"

    generate(tmp_path, manifest)
    assert verify(tmp_path, manifest) == 0

    sample.write_text("tampered\n", encoding="utf-8")
    assert verify(tmp_path, manifest) == 1


def test_vault_encrypt_decrypt_roundtrip(tmp_path: Path) -> None:
    plain = tmp_path / "secret.txt"
    enc = tmp_path / "secret.enc"
    restored = tmp_path / "restored.txt"
    plain.write_text("sensitive-payload", encoding="utf-8")

    encrypt_file(plain, enc, "test-passphrase-123")
    assert enc.exists()
    assert enc.read_bytes() != plain.read_bytes()

    decrypt_file(enc, restored, "test-passphrase-123")
    assert restored.read_text(encoding="utf-8") == "sensitive-payload"
security-ci.yml

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
