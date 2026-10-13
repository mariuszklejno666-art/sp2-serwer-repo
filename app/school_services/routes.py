from __future__ import annotations

from datetime import date, datetime, time, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from flask import Response, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.directory.service import DirectoryError, DirectoryService
from app.extensions import db
from app.monitoring_nvr import (
    SnapshotError,
    check_nvr,
    fetch_snapshot,
    panel_url,
    parse_nvr_endpoints,
)
from app.nas_snmp import SnmpError, fetch_storage_usage
from app.network_drives import (
    audit_share_group_mappings,
    check_smb,
    parse_nas_endpoints,
    parse_share_group_mappings,
)
from app.models import (
    AgentComputer,
    AgentJob,
    AudioPlaylist,
    AudioPlaylistEntry,
    AudioTrack,
    AuditLog,
    BellEvent,
    BellEventAudio,
    BellSchedule,
    SchoolCalendarException,
    WebBlockRule,
)
from app.permissions import is_administrator, is_school_management
from app.radio_calendar import DAY_STYLES, classify_school_day, month_calendar
from app.radio_library import AudioUploadError, save_audio_upload
from app.radio_player import (
    PlaybackError,
    playback_status,
    start_playlist as start_local_playlist,
    stop_playback,
)
from app.radio_scheduler import next_bell
from app.radio_speech import SpeechError, generate_speech
from app.radio_sources import RADIO_SOURCES
from app.web_filtering import (
    FILTERED_ROOMS,
    WebFilterValidationError,
    build_room_hostname_map,
    normalize_blocked_address,
    normalize_rooms,
)

from . import bp


def _administrator_required() -> None:
    if not is_administrator():
        abort(403)


def _management_required() -> None:
    if not is_school_management():
        abort(403)


def _audit(action: str, result: str, details: str) -> None:
    db.session.add(
        AuditLog(
            user_id=current_user.id,
            username=current_user.username,
            action=action,
            result=result,
            ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
            details=details[:500],
        )
    )


@bp.get("")
@login_required
def index():
    cards = [
        {
            "title": "Blokowanie stron",
            "description": "Lista domen blokowanych dla komputerów uczniowskich.",
            "endpoint": "school_services.web_filter",
            "status": "Aktywne" if current_app.config["WEB_FILTER_ENFORCEMENT_ENABLED"] else "Konfiguracja",
            "available": is_administrator(),
        },
        {
            "title": "Radiowęzeł",
            "description": "Dzwonki, komunikaty, muzyka i kalendarz dni wolnych.",
            "endpoint": "school_services.radio",
            "status": "Aktywne" if current_app.config["RADIO_PLAYBACK_ENABLED"] else "Projekt",
            "available": is_school_management(),
        },
        {
            "title": "Monitoring",
            "description": "Chroniony podgląd kamer dla kierownictwa szkoły.",
            "endpoint": "school_services.monitoring",
            "status": (
                "Aktywne"
                if current_app.config["MONITORING_STREAMS_ENABLED"]
                else "Konfiguracja"
                if current_app.config["MONITORING_NVR_ENDPOINTS"]
                else "Projekt"
            ),
            "available": is_school_management(),
        },
        {
            "title": "Elektroniczne ogłoszenia",
            "description": "Komunikaty szkolne z priorytetem, harmonogramem i grupą odbiorców.",
            "endpoint": "school_services.announcements_board",
            "status": "Projekt",
            "available": is_school_management(),
        },
        {
            "title": "Dyski sieciowe",
            "description": "Kontrola mapowania udziałów według grup AD.",
            "endpoint": "school_services.network_drives",
            "status": (
                "Aktywne"
                if current_app.config["NETWORK_DRIVE_SHARE_GROUPS"]
                else "Konfiguracja"
            ),
            "available": is_school_management(),
        },
    ]
    return render_template("school_services/index.html", cards=cards)


@bp.route("/web-filter", methods=["GET", "POST"])
@login_required
def web_filter():
    _administrator_required()
    if request.method == "POST":
        label = str(request.form.get("label", "")).strip()
        try:
            source_url, hostname = normalize_blocked_address(request.form.get("address", ""))
            rooms = normalize_rooms(request.form.getlist("rooms"))
            if not label:
                label = hostname
            if len(label) > 120:
                raise WebFilterValidationError("Nazwa reguły może mieć najwyżej 120 znaków.")
        except WebFilterValidationError as exc:
            flash(str(exc), "danger")
        else:
            rule = WebBlockRule(
                label=label,
                source_url=source_url,
                hostname=hostname,
                rooms=",".join(rooms),
                enabled=True,
                created_by=current_user.username,
            )
            db.session.add(rule)
            _audit("WEB_FILTER_RULE_CREATE", "SUCCESS", f"host={hostname}; rooms={','.join(rooms)}")
            db.session.commit()
            flash(
                "Reguła została zapisana. Kliknij „Zastosuj teraz”, żeby wysłać ją do komputerów.",
                "success",
            )
            return redirect(url_for("school_services.web_filter"))

    rules = db.session.scalars(
        db.select(WebBlockRule).order_by(WebBlockRule.enabled.desc(), WebBlockRule.hostname)
    ).all()
    return render_template(
        "school_services/web_filter.html",
        rules=rules,
        filtered_rooms=FILTERED_ROOMS,
        enforcement_enabled=current_app.config["WEB_FILTER_ENFORCEMENT_ENABLED"],
    )


@bp.post("/web-filter/<int:rule_id>/toggle")
@login_required
def toggle_web_filter_rule(rule_id: int):
    _administrator_required()
    rule = db.get_or_404(WebBlockRule, rule_id)
    rule.enabled = not rule.enabled
    _audit("WEB_FILTER_RULE_TOGGLE", "SUCCESS", f"host={rule.hostname}; enabled={rule.enabled}")
    db.session.commit()
    flash("Stan reguły został zmieniony. Kliknij „Zastosuj teraz”, żeby wysłać zmianę do komputerów.", "success")
    return redirect(url_for("school_services.web_filter"))


@bp.post("/web-filter/apply")
@login_required
def apply_web_filter():
    _administrator_required()
    if not current_app.config["WEB_FILTER_ENFORCEMENT_ENABLED"]:
        flash(
            "Egzekwowanie jest wyłączone w konfiguracji serwera "
            "(WEB_FILTER_ENFORCEMENT_ENABLED).",
            "danger",
        )
        return redirect(url_for("school_services.web_filter"))

    rules = db.session.scalars(db.select(WebBlockRule)).all()
    room_hosts = build_room_hostname_map(rules)

    queued = 0
    for agent_room, hostnames in room_hosts.items():
        agents = db.session.scalars(
            db.select(AgentComputer).where(AgentComputer.room == agent_room)
        ).all()
        for agent in agents:
            db.session.add(
                AgentJob(
                    computer=agent,
                    action="apply_web_filter",
                    payload={"hostnames": hostnames},
                    status="pending",
                )
            )
            queued += 1

    _audit("WEB_FILTER_APPLY", "SUCCESS", f"computers={queued}")
    db.session.commit()
    if queued:
        flash(f"Zlecono zastosowanie blokady na {queued} komputerach.", "success")
    else:
        flash("Nie znaleziono komputerów w salach objętych filtrowaniem.", "warning")
    return redirect(url_for("school_services.web_filter"))


@bp.get("/radio")
@login_required
def radio():
    _management_required()
    server_time = datetime.now(ZoneInfo("Europe/Warsaw"))
    try:
        year = int(request.args.get("year", server_time.year))
        month = int(request.args.get("month", server_time.month))
        selected = date(year, month, 1)
    except (TypeError, ValueError):
        selected = server_time.date().replace(day=1)

    exceptions = db.session.scalars(
        db.select(SchoolCalendarException).order_by(
            SchoolCalendarException.starts_on,
            SchoolCalendarException.label,
        )
    ).all()
    previous = (selected.replace(day=1) - timedelta(days=1)).replace(day=1)
    next_month = (
        selected.replace(day=28) + timedelta(days=4)
    ).replace(day=1)
    today = classify_school_day(server_time.date(), exceptions)
    schedules = db.session.scalars(
        db.select(BellSchedule).order_by(BellSchedule.name)
    ).unique().all()
    preview = next_bell(server_time, today, schedules)
    tracks = db.session.scalars(
        db.select(AudioTrack).order_by(AudioTrack.created_at.desc(), AudioTrack.title)
    ).all()
    playlists = db.session.scalars(
        db.select(AudioPlaylist).order_by(AudioPlaylist.name)
    ).unique().all()
    player_state_dir = Path(current_app.instance_path) / "radio_player"
    return render_template(
        "school_services/radio.html",
        server_time=server_time,
        playback_enabled=current_app.config["RADIO_PLAYBACK_ENABLED"],
        bell_automation_enabled=current_app.config["RADIO_BELL_AUTOMATION_ENABLED"],
        playback_status=playback_status(player_state_dir),
        weeks=month_calendar(selected.year, selected.month, exceptions),
        selected_month=selected,
        previous_month=previous,
        next_month=next_month,
        exceptions=exceptions,
        today=today,
        day_styles=DAY_STYLES,
        schedules=schedules,
        preview=preview,
        radio_sources=RADIO_SOURCES,
        tracks=tracks,
        playlists=playlists,
        upload_limit_mb=current_app.config["RADIO_UPLOAD_MAX_BYTES"] // (1024 * 1024),
    )



@bp.post("/radio/tracks")
@login_required
def upload_audio_track():
    _management_required()
    upload = request.files.get("audio_file")
    title = str(request.form.get("title", "")).strip()
    if request.form.get("authorized") != "on":
        flash("Potwierdź prawo szkoły do publicznego odtwarzania nagrania.", "danger")
        return redirect(url_for("school_services.radio"))
    if upload is None:
        flash("Wybierz plik MP3 lub WAV.", "danger")
        return redirect(url_for("school_services.radio"))

    upload_dir = Path(current_app.instance_path) / "radio_uploads"
    try:
        saved = save_audio_upload(
            upload,
            upload_dir,
            int(current_app.config["RADIO_UPLOAD_MAX_BYTES"]),
        )
        if not title:
            title = Path(saved.original_filename).stem
        if not title or len(title) > 160:
            raise AudioUploadError("Tytuł musi mieć od 1 do 160 znaków.")
    except AudioUploadError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("school_services.radio"))

    track = AudioTrack(
        title=title,
        original_filename=saved.original_filename,
        stored_filename=saved.stored_filename,
        media_type=saved.media_type,
        size_bytes=saved.size_bytes,
        created_by=current_user.username,
    )
    try:
        db.session.add(track)
        _audit(
            "RADIO_AUDIO_UPLOAD",
            "SUCCESS",
            f"title={title}; type={saved.media_type}; size={saved.size_bytes}",
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        (upload_dir / saved.stored_filename).unlink(missing_ok=True)
        raise

    flash("Plik został dodany do biblioteki. Odtwarzanie pozostaje wyłączone.", "success")
    return redirect(url_for("school_services.radio"))


@bp.post("/radio/playlists")
@login_required
def create_audio_playlist():
    _management_required()
    name = str(request.form.get("name", "")).strip()
    if not name or len(name) > 120:
        flash("Nazwa playlisty musi mieć od 1 do 120 znaków.", "danger")
        return redirect(url_for("school_services.radio"))
    if db.session.scalar(db.select(AudioPlaylist).where(AudioPlaylist.name == name)):
        flash("Playlista o tej nazwie już istnieje.", "danger")
        return redirect(url_for("school_services.radio"))

    playlist = AudioPlaylist(name=name, created_by=current_user.username)
    db.session.add(playlist)
    _audit("RADIO_PLAYLIST_CREATE", "SUCCESS", f"name={name}")
    db.session.commit()
    flash("Playlista została utworzona.", "success")
    return redirect(url_for("school_services.radio"))


@bp.post("/radio/playlists/<int:playlist_id>/tracks")
@login_required
def add_track_to_playlist(playlist_id: int):
    _management_required()
    playlist = db.get_or_404(AudioPlaylist, playlist_id)
    try:
        track_id = int(request.form.get("track_id", ""))
    except (TypeError, ValueError):
        flash("Wybierz prawidłowy utwór.", "danger")
        return redirect(url_for("school_services.radio"))
    track = db.get_or_404(AudioTrack, track_id)

    duplicate = db.session.scalar(
        db.select(AudioPlaylistEntry).where(
            AudioPlaylistEntry.playlist_id == playlist.id,
            AudioPlaylistEntry.track_id == track.id,
        )
    )
    if duplicate:
        flash("Ten utwór jest już na playliście.", "danger")
        return redirect(url_for("school_services.radio"))

    next_position = max((entry.position for entry in playlist.entries), default=0) + 1
    entry = AudioPlaylistEntry(
        playlist=playlist,
        track=track,
        position=next_position,
        created_by=current_user.username,
    )
    db.session.add(entry)
    _audit(
        "RADIO_PLAYLIST_TRACK_ADD",
        "SUCCESS",
        f"playlist={playlist.name}; track={track.title}; position={next_position}",
    )
    db.session.commit()
    flash("Utwór został dodany do playlisty.", "success")
    return redirect(url_for("school_services.radio"))


def _normalize_playlist_positions(playlist: AudioPlaylist) -> None:
    entries = db.session.scalars(
        db.select(AudioPlaylistEntry)
        .where(AudioPlaylistEntry.playlist_id == playlist.id)
        .order_by(AudioPlaylistEntry.position, AudioPlaylistEntry.id)
    ).all()
    for index, entry in enumerate(entries, start=1):
        entry.position = -index
    db.session.flush()
    for index, entry in enumerate(entries, start=1):
        entry.position = index


@bp.post("/radio/playlist-entries/<int:entry_id>/move")
@login_required
def move_playlist_entry(entry_id: int):
    _management_required()
    entry = db.get_or_404(AudioPlaylistEntry, entry_id)
    direction = str(request.form.get("direction", "")).strip()
    entries = sorted(entry.playlist.entries, key=lambda item: item.position)
    index = entries.index(entry)
    target_index = index - 1 if direction == "up" else index + 1 if direction == "down" else index
    if direction not in {"up", "down"}:
        abort(400)
    if 0 <= target_index < len(entries):
        target = entries[target_index]
        old_position = entry.position
        entry.position = -1
        db.session.flush()
        target.position = old_position
        db.session.flush()
        entry.position = target_index + 1
        _audit(
            "RADIO_PLAYLIST_TRACK_MOVE",
            "SUCCESS",
            f"playlist={entry.playlist.name}; track={entry.track.title}; direction={direction}",
        )
        db.session.commit()
        flash("Kolejność playlisty została zmieniona.", "success")
    else:
        flash("Utwór jest już na skraju playlisty.", "info")
    return redirect(url_for("school_services.radio"))


@bp.post("/radio/playlist-entries/<int:entry_id>/remove")
@login_required
def remove_playlist_entry(entry_id: int):
    _management_required()
    entry = db.get_or_404(AudioPlaylistEntry, entry_id)
    playlist = entry.playlist
    track_title = entry.track.title
    db.session.delete(entry)
    db.session.flush()
    _normalize_playlist_positions(playlist)
    _audit(
        "RADIO_PLAYLIST_TRACK_REMOVE",
        "SUCCESS",
        f"playlist={playlist.name}; track={track_title}",
    )
    db.session.commit()
    flash("Utwór został usunięty z playlisty.", "success")
    return redirect(url_for("school_services.radio"))


@bp.post("/radio/announcements/play")
@login_required
def play_spoken_announcement():
    _management_required()
    if not current_app.config["RADIO_PLAYBACK_ENABLED"]:
        flash("Odtwarzanie radiowęzła jest wyłączone w konfiguracji serwera.", "danger")
        return redirect(url_for("school_services.radio"))

    state_dir = Path(current_app.instance_path) / "radio_player"
    current = playback_status(state_dir)
    if current.running:
        flash(f"Najpierw zatrzymaj odtwarzanie „{current.playlist_name}”.", "danger")
        return redirect(url_for("school_services.radio"))

    text = str(request.form.get("announcement", ""))
    speech_dir = Path(current_app.instance_path) / "radio_speech"
    try:
        audio_path = generate_speech(
            text,
            speech_dir,
            binary=current_app.config["RADIO_TTS_BINARY"],
            voice=current_app.config["RADIO_TTS_VOICE"],
            speed=int(current_app.config["RADIO_TTS_SPEED"]),
        )
        start_local_playlist(
            playlist_name="Komunikat głosowy",
            tracks=[audio_path],
            upload_dir=speech_dir,
            state_dir=state_dir,
            binary=current_app.config["RADIO_PLAYER_BINARY"],
            audio_device=current_app.config["RADIO_AUDIO_DEVICE"],
        )
    except (SpeechError, PlaybackError) as exc:
        _audit("RADIO_ANNOUNCEMENT_PLAY", "FAILURE", f"error={exc}")
        db.session.commit()
        flash(str(exc), "danger")
    else:
        _audit(
            "RADIO_ANNOUNCEMENT_PLAY",
            "SUCCESS",
            f"characters={len(' '.join(text.split()))}",
        )
        db.session.commit()
        flash("Komunikat jest odtwarzany przez wzmacniacz.", "success")
    return redirect(url_for("school_services.radio"))


@bp.post("/radio/playlists/<int:playlist_id>/play")
@login_required
def play_audio_playlist(playlist_id: int):
    _management_required()
    if not current_app.config["RADIO_PLAYBACK_ENABLED"]:
        flash("Odtwarzanie radiowęzła jest wyłączone w konfiguracji serwera.", "danger")
        return redirect(url_for("school_services.radio"))

    playlist = db.get_or_404(AudioPlaylist, playlist_id)
    upload_dir = Path(current_app.instance_path) / "radio_uploads"
    tracks = [
        upload_dir / entry.track.stored_filename
        for entry in sorted(playlist.entries, key=lambda item: item.position)
    ]
    try:
        start_local_playlist(
            playlist_name=playlist.name,
            tracks=tracks,
            upload_dir=upload_dir,
            state_dir=Path(current_app.instance_path) / "radio_player",
            binary=current_app.config["RADIO_PLAYER_BINARY"],
            audio_device=current_app.config["RADIO_AUDIO_DEVICE"],
        )
    except PlaybackError as exc:
        _audit("RADIO_PLAYBACK_START", "FAILURE", f"playlist={playlist.name}; error={exc}")
        db.session.commit()
        flash(str(exc), "danger")
    else:
        _audit("RADIO_PLAYBACK_START", "SUCCESS", f"playlist={playlist.name}")
        db.session.commit()
        flash("Odtwarzanie przez wzmacniacz zostało uruchomione.", "success")
    return redirect(url_for("school_services.radio"))


@bp.post("/radio/playback/stop")
@login_required
def stop_audio_playback():
    _management_required()
    stopped = stop_playback(Path(current_app.instance_path) / "radio_player")
    _audit("RADIO_PLAYBACK_STOP", "SUCCESS", f"stopped={stopped}")
    db.session.commit()
    flash(
        "Odtwarzanie zostało zatrzymane."
        if stopped
        else "Odtwarzacz nie był uruchomiony.",
        "success" if stopped else "info",
    )
    return redirect(url_for("school_services.radio"))


@bp.post("/radio/bell-schedules")
@login_required
def create_bell_schedule():
    _management_required()
    name = str(request.form.get("name", "")).strip().lower()
    if not name or len(name) > 64:
        flash("Nazwa planu musi mieć od 1 do 64 znaków.", "danger")
        return redirect(url_for("school_services.radio"))
    if db.session.scalar(db.select(BellSchedule).where(BellSchedule.name == name)):
        flash("Plan o tej nazwie już istnieje.", "danger")
        return redirect(url_for("school_services.radio"))

    schedule = BellSchedule(name=name, created_by=current_user.username)
    db.session.add(schedule)
    _audit("RADIO_BELL_SCHEDULE_CREATE", "SUCCESS", f"name={name}")
    db.session.commit()
    flash("Plan dzwonków został dodany w trybie symulacji.", "success")
    return redirect(url_for("school_services.radio"))


@bp.post("/radio/bell-schedules/<int:schedule_id>/events")
@login_required
def create_bell_event(schedule_id: int):
    _management_required()
    schedule = db.get_or_404(BellSchedule, schedule_id)
    label = str(request.form.get("label", "")).strip()
    try:
        time_of_day = time.fromisoformat(str(request.form.get("time_of_day", "")))
        if not label or len(label) > 120:
            raise ValueError
    except ValueError:
        flash("Podaj poprawną nazwę i godzinę dzwonka.", "danger")
        return redirect(url_for("school_services.radio"))

    duplicate = db.session.scalar(
        db.select(BellEvent).where(
            BellEvent.schedule_id == schedule.id,
            BellEvent.time_of_day == time_of_day,
        )
    )
    if duplicate:
        flash("W tym planie istnieje już dzwonek o tej godzinie.", "danger")
        return redirect(url_for("school_services.radio"))

    event = BellEvent(
        schedule=schedule,
        label=label,
        time_of_day=time_of_day,
        created_by=current_user.username,
    )
    db.session.add(event)
    _audit(
        "RADIO_BELL_EVENT_CREATE",
        "SUCCESS",
        f"schedule={schedule.name}; time={time_of_day}; label={label}",
    )
    db.session.commit()
    flash("Godzina została dodana. Dźwięk nadal nie jest uruchamiany.", "success")
    return redirect(url_for("school_services.radio"))


@bp.post("/radio/bell-events/<int:event_id>/toggle")
@login_required
def toggle_bell_event(event_id: int):
    _management_required()
    event = db.get_or_404(BellEvent, event_id)
    event.enabled = not event.enabled
    _audit("RADIO_BELL_EVENT_TOGGLE", "SUCCESS", f"id={event.id}; enabled={event.enabled}")
    db.session.commit()
    flash("Stan godziny został zmieniony.", "success")
    return redirect(url_for("school_services.radio"))


@bp.post("/radio/bell-events/<int:event_id>/audio")
@login_required
def assign_bell_event_audio(event_id: int):
    _management_required()
    event = db.get_or_404(BellEvent, event_id)
    try:
        track_id = int(request.form.get("track_id", ""))
    except (TypeError, ValueError):
        flash("Wybierz prawidłowy plik dźwiękowy.", "danger")
        return redirect(url_for("school_services.radio"))
    track = db.get_or_404(AudioTrack, track_id)
    if not track.enabled:
        flash("Wybrany plik dźwiękowy jest wyłączony.", "danger")
        return redirect(url_for("school_services.radio"))

    assignment = event.audio_assignment
    if assignment is None:
        assignment = BellEventAudio(
            event=event,
            track=track,
            created_by=current_user.username,
        )
        db.session.add(assignment)
    else:
        assignment.track = track
        assignment.created_by = current_user.username
    _audit(
        "RADIO_BELL_AUDIO_ASSIGN",
        "SUCCESS",
        f"event={event.id}; schedule={event.schedule.name}; track={track.title}",
    )
    db.session.commit()
    flash("Dźwięk został przypisany do godziny dzwonka.", "success")
    return redirect(url_for("school_services.radio"))


@bp.post("/radio/calendar-exceptions")
@login_required
def create_radio_exception():
    _management_required()
    label = str(request.form.get("label", "")).strip()
    kind = str(request.form.get("kind", "break")).strip()
    schedule = str(request.form.get("schedule", "brak")).strip() or "brak"
    try:
        starts_on = date.fromisoformat(str(request.form.get("starts_on", "")))
        ends_on = date.fromisoformat(str(request.form.get("ends_on", "")))
        if not label or len(label) > 160:
            raise ValueError
        if ends_on < starts_on:
            raise ValueError
        if kind not in {"break", "special", "school"}:
            raise ValueError
    except ValueError:
        flash("Sprawdź nazwę, daty i rodzaj wyjątku.", "danger")
        return redirect(url_for("school_services.radio"))

    lessons = request.form.get("lessons") == "on"
    bells = request.form.get("bells") == "on"
    item = SchoolCalendarException(
        label=label,
        starts_on=starts_on,
        ends_on=ends_on,
        kind=kind,
        lessons=lessons,
        bells=bells,
        schedule=schedule[:64],
        created_by=current_user.username,
    )
    db.session.add(item)
    _audit("RADIO_CALENDAR_CREATE", "SUCCESS", f"label={label}; {starts_on}..{ends_on}")
    db.session.commit()
    flash("Wyjątek kalendarza został zapisany. Odtwarzanie nadal jest wyłączone.", "success")
    return redirect(url_for("school_services.radio", year=starts_on.year, month=starts_on.month))


@bp.post("/radio/calendar-exceptions/<int:exception_id>/toggle")
@login_required
def toggle_radio_exception(exception_id: int):
    _management_required()
    item = db.get_or_404(SchoolCalendarException, exception_id)
    item.enabled = not item.enabled
    _audit("RADIO_CALENDAR_TOGGLE", "SUCCESS", f"id={item.id}; enabled={item.enabled}")
    db.session.commit()
    flash("Stan wyjątku został zmieniony.", "success")
    return redirect(url_for("school_services.radio"))


@bp.get("/monitoring")
@login_required
def monitoring():
    _management_required()
    endpoints = parse_nvr_endpoints(current_app.config["MONITORING_NVR_ENDPOINTS"])
    checks = [
        check_nvr(item, current_app.config["MONITORING_NVR_TIMEOUT"])
        for item in endpoints
    ]
    return render_template(
        "school_services/monitoring.html",
        streams_enabled=current_app.config["MONITORING_STREAMS_ENABLED"],
        nvr_checks=checks,
        snapshot_nvr_name=current_app.config["MONITORING_SNAPSHOT_NVR_NAME"],
        snapshot_configured=bool(
            current_app.config["MONITORING_SNAPSHOT_USERNAME"]
            and current_app.config["MONITORING_SNAPSHOT_PASSWORD"]
        ),
    )


@bp.get("/monitoring/snapshot/<name>")
@login_required
def monitoring_snapshot(name: str):
    _management_required()
    pilot_name = current_app.config["MONITORING_SNAPSHOT_NVR_NAME"]
    username = current_app.config["MONITORING_SNAPSHOT_USERNAME"]
    password = current_app.config["MONITORING_SNAPSHOT_PASSWORD"]
    if not pilot_name or name != pilot_name or not username or not password:
        abort(404)

    endpoints = parse_nvr_endpoints(current_app.config["MONITORING_NVR_ENDPOINTS"])
    endpoint = next((item for item in endpoints if item.name == name), None)
    if endpoint is None:
        abort(404)

    try:
        data, content_type = fetch_snapshot(
            endpoint=endpoint,
            username=username,
            password=password,
            channel=current_app.config["MONITORING_SNAPSHOT_CHANNEL"],
            timeout=current_app.config["MONITORING_SNAPSHOT_TIMEOUT"],
        )
    except SnapshotError as exc:
        _audit("MONITORING_SNAPSHOT_FETCH", "FAILURE", f"name={name}; error={exc}")
        db.session.commit()
        abort(502)

    _audit("MONITORING_SNAPSHOT_FETCH", "SUCCESS", f"name={name}")
    db.session.commit()
    return Response(data, mimetype=content_type, headers={"Cache-Control": "no-store"})


@bp.get("/monitoring/open/<name>")
@login_required
def open_monitoring_panel(name: str):
    _management_required()
    endpoints = parse_nvr_endpoints(current_app.config["MONITORING_NVR_ENDPOINTS"])
    endpoint = next((item for item in endpoints if item.name == name), None)
    if endpoint is None:
        abort(404)

    target = panel_url(endpoint)
    _audit("MONITORING_PANEL_OPEN", "SUCCESS", f"name={endpoint.name}; host={endpoint.host}")
    db.session.commit()
    return redirect(target)


@bp.get("/network-drives")
@login_required
def network_drives():
    _management_required()
    endpoints = parse_nas_endpoints(current_app.config["NETWORK_DRIVE_ENDPOINTS"])
    checks = [
        check_smb(item, current_app.config["NETWORK_DRIVE_SMB_TIMEOUT"])
        for item in endpoints
    ]

    mappings = parse_share_group_mappings(current_app.config["NETWORK_DRIVE_SHARE_GROUPS"])
    share_audit: list[dict[str, object]] = []
    directory_error = None
    if mappings:
        try:
            ad_groups = DirectoryService().groups(limit=0)
        except DirectoryError as exc:
            directory_error = str(exc)
        else:
            share_audit = audit_share_group_mappings(mappings, ad_groups)

    volumes = []
    snmp_error = None
    snmp_host = current_app.config["NETWORK_DRIVE_SNMP_HOST"]
    snmp_community = current_app.config["NETWORK_DRIVE_SNMP_COMMUNITY"]
    if snmp_host and snmp_community:
        try:
            volumes = fetch_storage_usage(
                snmp_host,
                snmp_community,
                port=current_app.config["NETWORK_DRIVE_SNMP_PORT"],
                timeout=current_app.config["NETWORK_DRIVE_SNMP_TIMEOUT"],
            )
        except SnmpError as exc:
            snmp_error = str(exc)

    return render_template(
        "school_services/network_drives.html",
        nas_checks=checks,
        share_audit=share_audit,
        directory_error=directory_error,
        volumes=volumes,
        snmp_error=snmp_error,
        snmp_configured=bool(snmp_host and snmp_community),
        volume_warning_percent=current_app.config["NETWORK_DRIVE_VOLUME_WARNING_PERCENT"],
    )
