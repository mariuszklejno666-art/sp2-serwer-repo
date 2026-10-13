from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "agent-windows" / "migrate-entra-to-samba.ps1"


def test_ca_is_imported_before_first_api_request():
    script = SCRIPT.read_text(encoding="utf-8-sig")
    main = script[script.index("\nAssert-Administrator\n") + 1 :]

    ca_import = main.index("Install-BundledCa $root")
    first_api_operation = main.index("$nameResponse = Get-ComputerNamePreview")

    assert ca_import < first_api_operation
    assert "StoreName]::Root" in script
    assert "StoreLocation]::LocalMachine" in script
    assert "$store.Add($certificate)" in script


def test_ca_import_is_idempotent_and_requires_bundled_file():
    script = SCRIPT.read_text(encoding="utf-8-sig")

    assert "Brak certyfikatu CA wymaganego do HTTPS" in script
    assert "Where-Object Thumbprint -eq $certificate.Thumbprint" in script
    assert "if ($existing.Count -eq 0)" in script
