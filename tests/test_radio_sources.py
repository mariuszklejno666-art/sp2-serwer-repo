from __future__ import annotations

import io

from app.extensions import db
from app.models import AudioPlaylist, AudioPlaylistEntry, AudioTrack
from app.radio_sources import RADIO_SOURCES


def test_radio_sources_only_use_official_https_pages():
    sources = {item.key: item for item in RADIO_SOURCES}

    assert set(sources) == {"radio-zet", "rmf-fm"}
    assert sources["radio-zet"].public_url.startswith("https://player.radiozet.pl/")
    assert sources["rmf-fm"].public_url.startswith("https://www.rmfon.pl/")
    assert all(item.public_url.startswith("https://") for item in RADIO_SOURCES)


def test_no_external_source_is_enabled_for_school_broadcast():
    assert not any(item.school_broadcast_allowed for item in RADIO_SOURCES)


def test_radio_panel_shows_library_without_spotify(authenticated_client):
    response = authenticated_client.get("/school-services/radio")

    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "Biblioteka muzyki" in page
    assert "Radio ZET" in page
    assert "RMF FM" in page
    assert "Spotify" not in page
    assert "Potwierdzam, że szkoła ma prawo" in page


def test_management_can_upload_mp3_and_build_playlist(
    app,
    authenticated_client,
    tmp_path,
):
    app.instance_path = str(tmp_path)
    response = authenticated_client.post(
        "/school-services/radio/tracks",
        data={
            "title": "Hymn szkoły",
            "authorized": "on",
            "audio_file": (io.BytesIO(b"ID3" + b"audio-data"), "hymn.mp3"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 302

    with app.app_context():
        track = db.session.scalar(db.select(AudioTrack))
        assert track is not None
        assert track.title == "Hymn szkoły"
        assert track.media_type == "mp3"
        assert track.stored_filename != track.original_filename
        assert (tmp_path / "radio_uploads" / track.stored_filename).is_file()

    response = authenticated_client.post(
        "/school-services/radio/playlists",
        data={"name": "Przerwa obiadowa"},
    )
    assert response.status_code == 302

    with app.app_context():
        playlist = db.session.scalar(db.select(AudioPlaylist))
        track = db.session.scalar(db.select(AudioTrack))
        playlist_id = playlist.id
        track_id = track.id

    response = authenticated_client.post(
        f"/school-services/radio/playlists/{playlist_id}/tracks",
        data={"track_id": str(track_id)},
    )
    assert response.status_code == 302

    with app.app_context():
        entry = db.session.scalar(db.select(AudioPlaylistEntry))
        assert entry is not None
        assert entry.position == 1


def test_upload_rejects_wrong_extension_and_missing_rights(
    app,
    authenticated_client,
    tmp_path,
):
    app.instance_path = str(tmp_path)
    response = authenticated_client.post(
        "/school-services/radio/tracks",
        data={
            "authorized": "on",
            "audio_file": (io.BytesIO(b"not-audio"), "program.exe"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert "Dozwolone są wyłącznie pliki MP3 i WAV." in response.get_data(as_text=True)

    response = authenticated_client.post(
        "/school-services/radio/tracks",
        data={
            "audio_file": (io.BytesIO(b"ID3audio"), "utwor.mp3"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert "Potwierdź prawo szkoły" in response.get_data(as_text=True)

    with app.app_context():
        assert db.session.scalar(db.select(AudioTrack)) is None


def test_management_can_reorder_and_remove_playlist_entries(
    app,
    authenticated_client,
):
    with app.app_context():
        playlist = AudioPlaylist(name="Poranek", created_by="admin")
        tracks = [
            AudioTrack(
                title=title,
                original_filename=f"{index}.mp3",
                stored_filename=f"{index}.mp3",
                media_type="mp3",
                size_bytes=10,
                created_by="admin",
            )
            for index, title in enumerate(("Pierwszy", "Drugi", "Trzeci"), start=1)
        ]
        db.session.add_all([playlist, *tracks])
        db.session.flush()
        entries = [
            AudioPlaylistEntry(
                playlist=playlist,
                track=track,
                position=index,
                created_by="admin",
            )
            for index, track in enumerate(tracks, start=1)
        ]
        db.session.add_all(entries)
        db.session.commit()
        second_id = entries[1].id
        first_id = entries[0].id

    response = authenticated_client.post(
        f"/school-services/radio/playlist-entries/{second_id}/move",
        data={"direction": "up"},
    )
    assert response.status_code == 302

    with app.app_context():
        ordered = db.session.scalars(
            db.select(AudioPlaylistEntry).order_by(AudioPlaylistEntry.position)
        ).all()
        assert [entry.track.title for entry in ordered] == [
            "Drugi",
            "Pierwszy",
            "Trzeci",
        ]
        assert [entry.position for entry in ordered] == [1, 2, 3]

    response = authenticated_client.post(
        f"/school-services/radio/playlist-entries/{first_id}/remove",
    )
    assert response.status_code == 302

    with app.app_context():
        ordered = db.session.scalars(
            db.select(AudioPlaylistEntry).order_by(AudioPlaylistEntry.position)
        ).all()
        assert [entry.track.title for entry in ordered] == ["Drugi", "Trzeci"]
        assert [entry.position for entry in ordered] == [1, 2]


def test_playlist_move_rejects_invalid_direction(app, authenticated_client):
    with app.app_context():
        playlist = AudioPlaylist(name="Test", created_by="admin")
        track = AudioTrack(
            title="Utwór",
            original_filename="track.mp3",
            stored_filename="track.mp3",
            media_type="mp3",
            size_bytes=10,
            created_by="admin",
        )
        entry = AudioPlaylistEntry(
            playlist=playlist,
            track=track,
            position=1,
            created_by="admin",
        )
        db.session.add_all([playlist, track, entry])
        db.session.commit()
        entry_id = entry.id

    response = authenticated_client.post(
        f"/school-services/radio/playlist-entries/{entry_id}/move",
        data={"direction": "sideways"},
    )
    assert response.status_code == 400
