"""Download public OTRF Sysmon and raw UNSW-NB15 research datasets.

Run from the repository root with ``python backend/ml/training/download_datasets.py``.
Large source files are kept under the git-ignored ``backend/datasets`` directory.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATASET_DIR = BACKEND_DIR / "datasets"
OTRF_RAW = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
UNSW_ZENODO = "https://zenodo.org/records/10140548/files/"
FEATURES_MIRROR = "https://huggingface.co/datasets/Mouwiya/UNSW-NB15/resolve/main/"

# A broader background-activity capture plus representative credential access,
# process-access/injection, and registry persistence Atomic captures.
SYSmon_ARCHIVES = {
    "purplesharp_ad_playbook_I.zip": "datasets/atomic/windows/lateral_movement/host/purplesharp_ad_playbook_I.zip",
    "empire_mimikatz_logonpasswords.zip": "datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip",
    "empire_dllinjection_LoadLibrary_CreateRemoteThread.zip": "datasets/atomic/windows/defense_evasion/host/empire_dllinjection_LoadLibrary_CreateRemoteThread.zip",
    "empire_persistence_registry_run_keys_standard.zip": "datasets/atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_standard_user.zip",
    "cmd_bitsadmin_download_psh_script.zip": "datasets/atomic/windows/defense_evasion/host/cmd_bitsadmin_download_psh_script.zip",
}
UNSW_FILES = {
    "UNSW-NB15_1.csv": ("CSV Files/UNSW-NB15_1.csv",),
    "UNSW-NB15_2.csv": ("CSV Files/UNSW-NB15_2.csv",),
    "UNSW-NB15_3.csv": ("CSV Files/UNSW-NB15_3.csv",),
    "UNSW-NB15_4.csv": ("CSV Files/UNSW-NB15_4.csv",),
    "NUSW-NB15_features.csv": ("NUSW-NB15_features.csv", "UNSW-NB15_features.csv"),
}
MIN_BYTES = {"UNSW-NB15_1.csv": 10_000_000, "UNSW-NB15_2.csv": 10_000_000,
             "UNSW-NB15_3.csv": 10_000_000, "UNSW-NB15_4.csv": 10_000_000,
             "NUSW-NB15_features.csv": 1_000}


def _download(url: str, destination: Path, minimum_bytes: int = 1) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file() and destination.stat().st_size >= minimum_bytes:
        print(f"Present: {destination.name} ({destination.stat().st_size:,} bytes)")
        return
    temp = destination.with_suffix(destination.suffix + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": "CyberGuardX-dataset-fetch/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=90) as response, temp.open("wb") as out:
            shutil.copyfileobj(response, out, length=1024 * 1024)
    except Exception:
        temp.unlink(missing_ok=True)
        raise
    if temp.stat().st_size < minimum_bytes:
        temp.unlink(missing_ok=True)
        raise IOError(f"Downloaded file is too small to be valid: {url}")
    temp.replace(destination)
    digest_builder = hashlib.sha256()
    with destination.open("rb") as downloaded:
        for chunk in iter(lambda: downloaded.read(1024 * 1024), b""):
            digest_builder.update(chunk)
    digest = digest_builder.hexdigest()
    print(f"Downloaded: {destination.name} ({destination.stat().st_size:,} bytes; sha256={digest})")


def _safe_extract(archive: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        for item in zf.infolist():
            relative = PurePosixPath(item.filename)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError(f"Unsafe archive path: {item.filename}")
            destination = target.joinpath(*relative.parts)
            if item.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(item) as source, destination.open("wb") as out:
                    shutil.copyfileobj(source, out)


def _download_sysmon() -> None:
    destination = DATASET_DIR / "sysmon"
    for name, relative_url in SYSmon_ARCHIVES.items():
        archive = destination / "archives" / name
        _download(OTRF_RAW + relative_url, archive, minimum_bytes=10_000)
        extracted = destination / "captures" / Path(name).stem
        if not any(extracted.rglob("*.json")) and not any(extracted.rglob("*.jsonl")):
            _safe_extract(archive, extracted)
    manifest = {"source": "https://github.com/OTRF/Security-Datasets",
                "license": "MIT", "captures": list(SYSmon_ARCHIVES)}
    (destination / "SOURCE.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def _download_unsw() -> None:
    destination = DATASET_DIR / "unsw_nb15"
    for filename, paths in UNSW_FILES.items():
        if filename == "NUSW-NB15_features.csv":
            # The canonical metadata filename is commonly spelled UNSW; retain
            # the requested NUSW compatibility name locally.
            target = destination / filename
        else:
            target = destination / filename
        if target.is_file() and target.stat().st_size >= MIN_BYTES[filename]:
            print(f"Present: {filename} ({target.stat().st_size:,} bytes)")
            continue
        errors = []
        if filename == "NUSW-NB15_features.csv":
            candidates = [FEATURES_MIRROR + "NUSW-NB15_features.csv",
                          FEATURES_MIRROR + "UNSW-NB15_features.csv"]
        else:
            candidates = [UNSW_ZENODO + filename + "?download=1"]
        for candidate in candidates:
            try:
                _download(candidate, target, MIN_BYTES[filename])
            except (urllib.error.URLError, urllib.error.HTTPError, IOError) as exc:
                errors.append(f"{candidate}: {exc}")
            if target.is_file() and target.stat().st_size >= MIN_BYTES[filename]:
                break
        if not target.is_file() or target.stat().st_size < MIN_BYTES[filename]:
            raise RuntimeError(f"Could not fetch {filename}. Tried: " + " | ".join(errors[-4:]))
    # Check the raw parts are CSV-like and the metadata exposes graph identifiers.
    for name in list(UNSW_FILES)[:4]:
        with (destination / name).open("rb") as stream:
            sample = stream.read(2048)
        if sample.count(b",") < 10:
            raise ValueError(f"{name} does not look like a raw UNSW-NB15 CSV")
    metadata = (destination / "NUSW-NB15_features.csv").read_text(encoding="utf-8-sig", errors="replace").lower()
    for column in ("srcip", "sport", "dstip", "dsport", "proto", "attack_cat"):
        if column not in metadata:
            raise ValueError(f"UNSW-NB15 feature metadata is missing {column}")
    (destination / "SOURCE.json").write_text(json.dumps({
        "source": "UNSW Canberra dataset mirrored at https://zenodo.org/records/10140548; feature metadata at https://huggingface.co/datasets/Mouwiya/UNSW-NB15",
        "files": list(UNSW_FILES), "citation": "Moustafa and Slay, MilCIS 2015, doi:10.1109/MilCIS.2015.7348942"
    }, indent=2), encoding="utf-8")


def main() -> None:
    _download_sysmon()
    _download_unsw()
    print(f"Datasets downloaded and verified under {DATASET_DIR}")


if __name__ == "__main__":
    main()
