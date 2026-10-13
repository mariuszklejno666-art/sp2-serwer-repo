"""Offline tests for the pinned, public-CA domain-repair release package."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import subprocess
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "sp2_ca_packager", ROOT / "scripts" / "package-domain-repair-with-ca.py"
)
assert SPEC is not None and SPEC.loader is not None
packager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packager)
PUBLIC_TEST_CA = ROOT / "agent-windows" / "domain-repair" / "test-fixtures" / "ca-test-only.crt"


def digests(path: Path) -> tuple[str, str]:
    raw = path.read_bytes()
    der = subprocess.check_output(
        ["openssl", "x509", "-in", str(path), "-outform", "DER"]
    )
    return hashlib.sha256(raw).hexdigest(), hashlib.sha256(der).hexdigest()


def make_artifact(path: Path, *, bad_path: bool = False) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        if bad_path:
            archive.writestr("../unexpected.txt", b"bad")
        archive.writestr("SP2-Serwis-Domeny-Portable.exe", b"public-test-binary")
        archive.writestr("SP2-Serwis-Domeny.exe", b"public-test-binary")
        archive.writestr("SP2-Serwis-Domeny.ps1", b"public-test-script")


def test_verified_public_ca_is_the_only_added_artifact(tmp_path: Path) -> None:
    source = tmp_path / "artifact.zip"
    output = tmp_path / "school-release.zip"
    make_artifact(source)
    file_sha, der_sha = digests(PUBLIC_TEST_CA)
    result = packager.package(
        source, PUBLIC_TEST_CA, output,
        expected_file_sha256=file_sha, expected_der_sha256=der_sha,
    )
    assert result == output
    with zipfile.ZipFile(source) as original:
        assert "sp2-internal-ca.crt" not in original.namelist()
    with zipfile.ZipFile(output) as bundle:
        assert bundle.read("sp2-internal-ca.crt") == PUBLIC_TEST_CA.read_bytes()
        assert bundle.read("SP2-Serwis-Domeny.ps1") == b"public-test-script"


def test_default_production_pin_rejects_fixture_without_writing(tmp_path: Path) -> None:
    source = tmp_path / "artifact.zip"
    output = tmp_path / "school-release.zip"
    make_artifact(source)
    with pytest.raises(ValueError, match="SHA-256"):
        packager.package(source, PUBLIC_TEST_CA, output)
    assert not output.exists()


def test_wrong_ca_fingerprint_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / "artifact.zip"
    output = tmp_path / "school-release.zip"
    make_artifact(source)
    file_sha, _ = digests(PUBLIC_TEST_CA)
    with pytest.raises(ValueError, match="DER"):
        packager.package(
            source, PUBLIC_TEST_CA, output,
            expected_file_sha256=file_sha, expected_der_sha256="0" * 64,
        )
    assert not output.exists()


def test_zip_path_traversal_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "artifact.zip"
    output = tmp_path / "school-release.zip"
    make_artifact(source, bad_path=True)
    file_sha, der_sha = digests(PUBLIC_TEST_CA)
    with pytest.raises(ValueError, match="Niebezpieczna"):
        packager.package(
            source, PUBLIC_TEST_CA, output,
            expected_file_sha256=file_sha, expected_der_sha256=der_sha,
        )
    assert not output.exists()
