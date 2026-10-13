import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "agent-windows"))

from web_filter_hosts import WEB_FILTER_END, WEB_FILTER_START, apply_web_filter_hosts


def test_apply_web_filter_hosts_creates_managed_block(tmp_path):
    hosts_path = tmp_path / "hosts"
    hosts_path.write_text("127.0.0.1 localhost\n", encoding="utf-8")

    applied = apply_web_filter_hosts(["Gry.Example.pl", "social.example.com"], hosts_path)

    content = hosts_path.read_text(encoding="utf-8")
    assert applied == 2
    assert "127.0.0.1 localhost" in content
    assert WEB_FILTER_START in content
    assert WEB_FILTER_END in content
    assert "127.0.0.1 gry.example.pl" in content
    assert "127.0.0.1 social.example.com" in content


def test_apply_web_filter_hosts_is_idempotent_and_replaces_previous_block(tmp_path):
    hosts_path = tmp_path / "hosts"
    hosts_path.write_text("127.0.0.1 localhost\n", encoding="utf-8")

    apply_web_filter_hosts(["old-domain.pl"], hosts_path)
    apply_web_filter_hosts(["new-domain.pl"], hosts_path)

    content = hosts_path.read_text(encoding="utf-8")
    assert content.count(WEB_FILTER_START) == 1
    assert "old-domain.pl" not in content
    assert "127.0.0.1 new-domain.pl" in content
    assert "127.0.0.1 localhost" in content


def test_apply_web_filter_hosts_clears_block_when_no_domains(tmp_path):
    hosts_path = tmp_path / "hosts"
    hosts_path.write_text("127.0.0.1 localhost\n", encoding="utf-8")

    apply_web_filter_hosts(["gry.example.pl"], hosts_path)
    applied = apply_web_filter_hosts([], hosts_path)

    content = hosts_path.read_text(encoding="utf-8")
    assert applied == 0
    assert WEB_FILTER_START not in content
    assert "gry.example.pl" not in content
    assert "127.0.0.1 localhost" in content


def test_apply_web_filter_hosts_deduplicates_and_ignores_blank_entries(tmp_path):
    hosts_path = tmp_path / "hosts"

    apply_web_filter_hosts(["gry.pl", "GRY.PL", "  ", ""], hosts_path)

    content = hosts_path.read_text(encoding="utf-8")
    assert content.count("gry.pl") == 1


def test_apply_web_filter_hosts_creates_file_when_missing(tmp_path):
    hosts_path = tmp_path / "nested" / "hosts"

    applied = apply_web_filter_hosts(["gry.pl"], hosts_path)

    assert applied == 1
    assert hosts_path.exists()
