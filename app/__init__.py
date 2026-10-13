from __future__ import annotations

import logging
import os
from logging.config import dictConfig
from pathlib import Path

import click
from dotenv import load_dotenv
from flask import Flask, abort, request

from .extensions import csrf, db, login_manager
from .services.diagnostics import DiagnosticsError, run_health_checks


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _configure_logging(level: str) -> None:
    dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "format": "%(asctime)s %(levelname)s %(name)s: %(message)s"
                }
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "default",
                }
            },
            "root": {
                "level": level,
                "handlers": ["console"],
            },
        }
    )


def create_app(config_name: str | None = None) -> Flask:
    # Plik .env musi zostać wczytany przed importem CONFIG_MAP,
    # ponieważ klasy konfiguracji odczytują zmienne środowiskowe
    # już podczas importowania app/config.py.
    load_dotenv(PROJECT_ROOT / ".env")

    from .config import CONFIG_MAP

    selected_config = config_name or os.getenv("FLASK_ENV", "development")
    config_class = CONFIG_MAP.get(
        selected_config,
        CONFIG_MAP["development"],
    )

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_class)
    if selected_config == "production":
        missing_or_insecure = []
        secret_key = str(app.config.get("SECRET_KEY", "")).strip()
        api_token = str(app.config.get("SP2_API_TOKEN", "")).strip()

        if not secret_key or secret_key == "development-only-change-me":
            missing_or_insecure.append("SECRET_KEY")
        if not api_token:
            missing_or_insecure.append("SP2_API_TOKEN")

        if missing_or_insecure:
            raise RuntimeError(
                "Brak bezpiecznej konfiguracji produkcyjnej: "
                + ", ".join(missing_or_insecure)
            )

    instance_dir = Path(app.instance_path)
    instance_dir.mkdir(parents=True, exist_ok=True)

    if not app.config.get("SQLALCHEMY_DATABASE_URI"):
        database_path = instance_dir / "sp2-admin.sqlite3"
        app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{database_path}"

    _configure_logging(app.config["LOG_LEVEL"])
    logging.getLogger(__name__).info(
        "Uruchamianie %s %s",
        app.config["APP_NAME"],
        app.config["APP_VERSION"],
    )

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(user_id: str) -> User | None:
        return db.session.get(User, int(user_id))

    from .agents import api_bp as agent_api_bp
    from .agents import bp as agents_bp
    from .api import bp as api_v1_bp
    from .auth import bp as auth_bp
    from .dashboard import bp as dashboard_bp
    from .directory import bp as directory_bp
    from .rooms import bp as rooms_bp
    from .school_services import bp as school_services_bp
    from .teachers import bp as teachers_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(agents_bp)
    app.register_blueprint(agent_api_bp)
    app.register_blueprint(api_v1_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(directory_bp)
    app.register_blueprint(rooms_bp)
    app.register_blueprint(school_services_bp)
    app.register_blueprint(teachers_bp)

    @app.before_request
    def protect_staging_instance():
        """Do not let a parallel preview send write requests to school services."""
        if not app.config["STAGING_READ_ONLY"]:
            return
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            # These links can open live services or trigger remote access.
            if request.endpoint in {
                "agents.remote_desktop_file",
                "school_services.open_monitoring_panel",
                "school_services.monitoring_snapshot",
            }:
                abort(403)
            return
        if request.endpoint in {"auth.login", "auth.logout", "directory.test_connection"}:
            return
        abort(403)

    @app.get("/health")
    def health() -> tuple[dict[str, str], int]:
        return {
            "status": "ok",
            "version": app.config["APP_VERSION"],
        }, 200

    @app.cli.command("init-db")
    def init_db_command() -> None:
        db.create_all()
        click.echo("Baza danych została zainicjalizowana.")

    @app.cli.command("doctor")
    def doctor_command() -> None:
        """Sprawdza stan aplikacji przy użyciu wspólnej diagnostyki."""
        try:
            for check in run_health_checks():
                click.echo(check.message)
        except DiagnosticsError as exc:
            raise click.ClickException(str(exc)) from exc

    @app.cli.command("radio-bells-tick")
    def radio_bells_tick_command() -> None:
        """Uruchamia dzwonek przypadający w bieżącej minucie."""
        from .radio_bells import run_bell_tick

        click.echo(run_bell_tick(app))

    @app.cli.command("create-admin")
    @click.option("--username", prompt="Login")
    @click.option("--full-name", prompt="Imię i nazwisko")
    @click.password_option(confirmation_prompt=True)
    def create_admin_command(
        username: str,
        full_name: str,
        password: str,
    ) -> None:
        db.create_all()
        normalized = username.strip().lower()

        existing_user = db.session.scalar(
            db.select(User).where(User.username == normalized)
        )
        if existing_user:
            raise click.ClickException(
                "Użytkownik o tym loginie już istnieje."
            )

        user = User(
            username=normalized,
            full_name=full_name.strip(),
            role="administrator",
        )
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        click.echo(f"Utworzono administratora: {normalized}")

    @app.cli.command("seed-preview-demo")
    def seed_preview_demo_command() -> None:
        """Populate only the isolated preview database with synthetic agents."""
        expected_uri = f"sqlite:///{PROJECT_ROOT / 'instance' / 'preview.sqlite3'}"
        if not (
            app.config["STAGING_READ_ONLY"]
            and app.config["PREVIEW_DEMO_DATA"]
            and app.config["SQLALCHEMY_DATABASE_URI"] == expected_uri
        ):
            raise click.ClickException("Dane demo wolno dodać tylko do oddzielnej bazy podglądu.")
        from .directory.preview_data import seed_agents

        click.echo(f"Dodano {seed_agents()} przykładowych agentów do bazy podglądu.")

    with app.app_context():
        db.create_all()

    return app
