"""Assemble an SP2 domain-repair ZIP with the pinned, public school CA.

Run on the school Linux server after downloading the Windows GitHub Actions
artifact. Never include or read the CA *private key*. The input artifact is
left unchanged; the output ZIP contains the verified public .crt sidecar.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import subprocess
import tempfile
import zipfile


SCHOOL_CA_FILE_SHA256 = "6206e04e6d6a8aef3676b95b2aed61ff55e48f39fc1b42ce6848da6ef7f43c43"
SCHOOL_CA_DER_SHA256 = "45581ba7ef494ddce73702c8f7f4174a5f8309ddf342f12b78c7a097f2bbcd33"
DEFAULT_CA = "/home/baraqda/sp2-internal-ca.crt"


def checked_ca_bytes(
    ca_path: Path,
    *,
    expected_file_sha256: str = SCHOOL_CA_FILE_SHA256,
    expected_der_sha256: str = SCHOOL_CA_DER_SHA256,
) -> bytes:
    data = ca_path.read_bytes()
    if not data or len(data) > 131072 or b"PRIVATE KEY" in data:
        raise ValueError("Nieprawidlowy plik CA: certyfikat musi byc publiczny.")
    if hashlib.sha256(data).hexdigest() != expected_file_sha256:
        raise ValueError("Niezgodna suma SHA-256 pliku szkolnego CA.")

    command = ["openssl", "x509", "-in", str(ca_path), "-outform", "DER"]
    result = subprocess.run(command, check=False, capture_output=True)
    if result.returncode != 0:
        result = subprocess.run(command + ["-inform", "DER"], check=False, capture_output=True)
    if result.returncode != 0 or not result.stdout:
        raise ValueError("Nie mozna odczytac publicznego certyfikatu X.509.")
    if hashlib.sha256(result.stdout).hexdigest() != expected_der_sha256:
        raise ValueError("Niezgodny odcisk DER SHA-256 szkolnego urzedu CA.")
    return data


def package(
    artifact_zip: Path,
    ca_path: Path,
    output_zip: Path,
    *,
    expected_file_sha256: str = SCHOOL_CA_FILE_SHA256,
    expected_der_sha256: str = SCHOOL_CA_DER_SHA256,
) -> Path:
    artifact_zip = artifact_zip.resolve()
    output_zip = output_zip.resolve()
    if artifact_zip == output_zip:
        raise ValueError("Wyjsciowy ZIP nie moze nadpisywac artefaktu GitHub Actions.")
    ca_data = checked_ca_bytes(
        ca_path,
        expected_file_sha256=expected_file_sha256,
        expected_der_sha256=expected_der_sha256,
    )

    output_zip.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = None
    try:
        with zipfile.ZipFile(artifact_zip, "r") as source:
            entries = source.infolist()
            names = [item.filename for item in entries]
            if len(names) != len(set(names)):
                raise ValueError("Wejsciowy ZIP zawiera zduplikowane sciezki.")
            for name in names:
                parts = PurePosixPath(name).parts
                if not name or name.startswith("/") or "\\" in name or ":" in name or ".." in parts:
                    raise ValueError("Niebezpieczna sciezka wejsciowego ZIP.")

            portable = [name for name in names if PurePosixPath(name).name == "SP2-Serwis-Domeny-Portable.exe"]
            if len(portable) != 1:
                raise ValueError("Artefakt musi zawierac dokladnie jeden plik SP2-Serwis-Domeny-Portable.exe.")
            directory = PurePosixPath(portable[0]).parent
            script_path = str(directory / "SP2-Serwis-Domeny.ps1")
            if script_path not in names:
                raise ValueError("Brakuje skryptu SP2-Serwis-Domeny.ps1 obok pliku Portable EXE.")
            dest = str(directory / "sp2-internal-ca.crt")
            if dest in names and source.read(dest) != ca_data:
                raise ValueError("Artefakt zawiera inny certyfikat CA. Przerwano.")
            handle = tempfile.NamedTemporaryFile(
                dir=output_zip.parent, prefix=".sp2-ca-", suffix=".zip", delete=False
            )
            tmp_path = Path(handle.name)
            handle.close()
            with zipfile.ZipFile(tmp_path, "w") as destination:
                for entry in entries:
                    destination.writestr(entry, source.read(entry.filename))
                if dest not in names:
                    destination.writestr(dest, ca_data, compress_type=zipfile.ZIP_DEFLATED)
        os.replace(tmp_path, output_zip)
        tmp_path = None
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)
    return output_zip


def main() -> None:
    parser = argparse.ArgumentParser(description="Weryfikuj szkolny CA i zloz pakiet SP2 Serwis Domeny.")
    parser.add_argument("artifact_zip", type=Path, help="ZIP pobrany z GitHub Actions")
    parser.add_argument("--ca", type=Path, default=Path(DEFAULT_CA), help="Sciezka do publicznego szkolnego CA")
    parser.add_argument("--output", type=Path, default=Path("SP2-Serwis-Domeny-z-CA.zip"))
    args = parser.parse_args()
    try:
        result = package(args.artifact_zip, args.ca, args.output)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        parser.exit(1, "BLAD: " + str(exc) + "\n")
    print("SP2 CA: SHA-256 DER i pliku potwierdzone; bez klucza prywatnego.")
    print("GOTOWA PACZKA: " + str(result))


if __name__ == "__main__":
    main()
