from unittest.mock import patch

from app.monitoring_nvr import (
    NvrEndpoint,
    SnapshotError,
    check_nvr,
    fetch_snapshot,
    panel_url,
    parse_nvr_endpoints,
)


def test_parse_nvr_endpoints_defaults_to_port_80():
    endpoints = parse_nvr_endpoints((
        "Sekretariat=192.168.0.227",
        "Portiernia=192.168.0.75:8080",
        "invalid",
    ))
    assert endpoints == (
        NvrEndpoint("Sekretariat", "192.168.0.227", 80),
        NvrEndpoint("Portiernia", "192.168.0.75", 8080),
    )


def test_parse_nvr_endpoints_ignores_bad_port():
    endpoints = parse_nvr_endpoints(("Sala=10.0.0.5:not-a-port",))
    assert endpoints == ()


def test_panel_url_uses_https_only_for_port_443():
    assert panel_url(NvrEndpoint("A", "10.0.0.1", 80)) == "http://10.0.0.1:80/"
    assert panel_url(NvrEndpoint("A", "10.0.0.1", 443)) == "https://10.0.0.1:443/"


def test_check_nvr_reports_unreachable_host():
    endpoint = NvrEndpoint("Sekretariat", "192.0.2.1", 80)
    with patch("app.monitoring_nvr.socket.create_connection", side_effect=OSError("timed out")):
        result = check_nvr(endpoint, timeout=0.1)

    assert result["reachable"] is False
    assert result["name"] == "Sekretariat"
    assert result["panel_url"] == "http://192.0.2.1:80/"


def test_check_nvr_reports_reachable_host():
    endpoint = NvrEndpoint("Sekretariat", "192.168.0.227", 80)
    with patch("app.monitoring_nvr.socket.create_connection") as mock_connect:
        mock_connect.return_value.__enter__.return_value = None
        result = check_nvr(endpoint, timeout=0.1)

    assert result["reachable"] is True


def test_fetch_snapshot_returns_bytes_and_content_type():
    endpoint = NvrEndpoint("Portiernia", "192.168.0.75", 80)

    class _FakeResponse:
        headers = {"Content-Type": "image/jpeg"}

        def read(self):
            return b"\xff\xd8\xff-fake-jpeg-bytes"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    with patch("app.monitoring_nvr.urllib.request.build_opener") as mock_build_opener:
        mock_build_opener.return_value.open.return_value = _FakeResponse()
        data, content_type = fetch_snapshot(
            endpoint=endpoint, username="viewer", password="secret", channel=1, timeout=1.0
        )

    assert data == b"\xff\xd8\xff-fake-jpeg-bytes"
    assert content_type == "image/jpeg"
    called_url = mock_build_opener.return_value.open.call_args[0][0]
    assert called_url == "http://192.168.0.75:80/ISAPI/Streaming/channels/101/picture"


def test_fetch_snapshot_raises_on_network_error():
    import urllib.error

    endpoint = NvrEndpoint("Portiernia", "192.168.0.75", 80)
    with patch("app.monitoring_nvr.urllib.request.build_opener") as mock_build_opener:
        mock_build_opener.return_value.open.side_effect = urllib.error.URLError("timed out")
        try:
            fetch_snapshot(endpoint=endpoint, username="viewer", password="secret")
            assert False, "expected SnapshotError"
        except SnapshotError:
            pass
