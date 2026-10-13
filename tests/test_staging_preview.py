from __future__ import annotations


def test_preview_shows_brand_and_motion_assets(authenticated_client, app):
    app.config["STAGING_READ_ONLY"] = True
    response = authenticated_client.get("/")
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "WERSJA ZAPASOWA" in page
    assert "matrix-server-loop.mp4" in page
    assert "matrix-server-poster.jpg" in page
    assert "sp2-logo.png" in page
    assert "mariusz-klejno-2026.jpg" in page
    assert "prefers-reduced-motion" in app.test_client().get(
        "/static/css/staging.css"
    ).get_data(as_text=True)

    for asset in (
        "/static/img/sp2-logo.png",
        "/static/img/mariusz-klejno-2026.jpg",
        "/static/img/matrix-server-poster.jpg",
        "/static/video/matrix-server-loop.mp4",
    ):
        assert authenticated_client.get(asset).status_code == 200


def test_existing_instance_keeps_its_current_skin(authenticated_client, app):
    app.config.update(STAGING_READ_ONLY=False, PREVIEW_THEME=False)
    page = authenticated_client.get("/").get_data(as_text=True)
    assert "css/staging.css" not in page
    assert "matrix-server-loop.mp4" not in page
    assert "WERSJA ZAPASOWA" not in page


def test_preview_blocks_changes_and_remote_access(authenticated_client, app):
    app.config["STAGING_READ_ONLY"] = True
    for path in (
        "/directory/users/new",
        "/agents/software",
        "/school-services/web-filter/apply",
    ):
        assert authenticated_client.post(path).status_code == 403

    for path in (
        "/agents/1/rdp",
        "/school-services/monitoring/snapshot/pilot",
        "/school-services/monitoring/open/pilot",
    ):
        assert authenticated_client.get(path).status_code == 403

    assert authenticated_client.get("/health").status_code == 200
