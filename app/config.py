from __future__ import annotations

import os
from pathlib import Path


def _split_setting(name: str, separator: str = ",") -> tuple[str, ...]:
    return tuple(
        value.strip()
        for value in os.getenv(name, "").split(separator)
        if value.strip()
    )


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "development-only-change-me")

    APP_NAME = os.getenv("APP_NAME", "SP2 ADMIN")
    APP_VERSION = os.getenv("APP_VERSION", "7.1.0-dev.1")
    APP_AUTHOR = os.getenv("APP_AUTHOR", "Mariusz Klejno")
    STAGING_READ_ONLY = os.getenv("SP2_STAGING_READ_ONLY", "false").lower() == "true"
    PREVIEW_THEME = os.getenv("SP2_PREVIEW_THEME", "false").lower() == "true"
    PREVIEW_DEMO_DATA = STAGING_READ_ONLY and os.getenv(
        "SP2_PREVIEW_DEMO_DATA", "false"
    ).lower() == "true"

    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URI",
        f"sqlite:///{Path.cwd() / 'instance' / 'sp2-admin.sqlite3'}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    WTF_CSRF_TIME_LIMIT = 3600
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "session")

    JSON_SORT_KEYS = False

    LDAP_URI = os.getenv("LDAP_URI", "")
    LDAP_BIND_DN = os.getenv("LDAP_BIND_DN", "")
    LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD", "")
    AD_JOIN_SERVICE_USER = os.getenv("AD_JOIN_SERVICE_USER", "")
    AD_JOIN_SERVICE_PASSWORD = os.getenv("AD_JOIN_SERVICE_PASSWORD", "")
    # Enable only after a Windows/Samba integration test with NTLM disabled.
    MACHINE_ACCOUNT_RECOVERY_ENABLED = os.getenv(
        "MACHINE_ACCOUNT_RECOVERY_ENABLED", "false"
    ).lower() == "true"
    LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "")

    LDAP_USE_SSL = os.getenv("LDAP_USE_SSL", "false").lower() == "true"
    LDAP_CONNECT_TIMEOUT = int(os.getenv("LDAP_CONNECT_TIMEOUT", "5"))
    LDAP_RECEIVE_TIMEOUT = int(os.getenv("LDAP_RECEIVE_TIMEOUT", "15"))
    LDAP_PAGE_SIZE = int(os.getenv("LDAP_PAGE_SIZE", "500"))
    LDAP_WRITE_BIND_DN = os.getenv("LDAP_WRITE_BIND_DN", "")
    LDAP_WRITE_BIND_PASSWORD = os.getenv("LDAP_WRITE_BIND_PASSWORD", "")
    AD_PASSWORD_MIN_LENGTH = int(os.getenv("AD_PASSWORD_MIN_LENGTH", "12"))
    AGENT_API_TOKEN = os.getenv("AGENT_API_TOKEN", "")
    AGENT_OFFLINE_AFTER_SECONDS = int(os.getenv("AGENT_OFFLINE_AFTER_SECONDS", "180"))
    # Próg zajętości dysku lokalnego (%), po przekroczeniu którego komputer
    # trafia na listę ostrzeżeń na dashboardzie.
    AGENT_DISK_WARNING_PERCENT_USED = float(
        os.getenv("AGENT_DISK_WARNING_PERCENT_USED", "90")
    )

    LDAP_WRITE_BIND_DN = os.getenv("LDAP_WRITE_BIND_DN", "")
    LDAP_WRITE_BIND_PASSWORD = os.getenv("LDAP_WRITE_BIND_PASSWORD", "")

    # Dane udostępniane przyszłemu kreatorowi dołączenia do domeny.
    # Lista OU używa separatora |, ponieważ distinguishedName zawiera przecinki.
    AD_DOMAIN_FQDN = os.getenv("AD_DOMAIN_FQDN", "").strip()
    AD_DOMAIN_NETBIOS = os.getenv("AD_DOMAIN_NETBIOS", "").strip()
    AD_DNS_SERVERS = _split_setting("AD_DNS_SERVERS")
    AD_JOIN_ALLOWED_OU_BASES = _split_setting(
        "AD_JOIN_ALLOWED_OU_BASES",
        separator="|",
    )
    AD_TEACHER_USER_OU = os.getenv(
        "AD_TEACHER_USER_OU",
        (
            f"OU=Nauczyciele,OU=Uzytkownicy,{LDAP_BASE_DN}"
            if LDAP_BASE_DN
            else ""
        ),
    ).strip()
    AD_TEACHER_COMPUTER_OU = os.getenv(
        "AD_TEACHER_COMPUTER_OU",
        (
            f"OU=Nauczyciele,OU=Komputery,{LDAP_BASE_DN}"
            if LDAP_BASE_DN
            else ""
        ),
    ).strip()

    AD_PASSWORD_MIN_LENGTH = int(
        os.getenv("AD_PASSWORD_MIN_LENGTH", "12")
    )
    # Hasło początkowe ustawiane przy tworzeniu konta wymaga zmiany przy
    # pierwszym logowaniu, więc może mieć niższy próg niż reset hasła.
    AD_NEW_USER_PASSWORD_MIN_LENGTH = int(
        os.getenv("AD_NEW_USER_PASSWORD_MIN_LENGTH", "6")
    )

    SP2_API_TOKEN = os.getenv(
        "SP2_API_TOKEN",
        os.getenv("AGENT_API_TOKEN", "")
    )

    AGENT_API_TOKEN = SP2_API_TOKEN
    SP2_API_TOKEN_PREVIOUS = os.getenv("SP2_API_TOKEN_PREVIOUS", "")
    # Osobny sekret służący tylko do pierwszej rejestracji nowych agentów.
    # Dla zgodności ze starszą konfiguracją domyślnie używa SP2_API_TOKEN.
    AGENT_ENROLLMENT_TOKEN = os.getenv(
        "AGENT_ENROLLMENT_TOKEN",
        SP2_API_TOKEN,
    ).strip()
    # Kod z paczki USB może zarejestrować serię komputerów w czasie ważności.
    AGENT_ENROLLMENT_MAX_USES = int(
        os.getenv("AGENT_ENROLLMENT_MAX_USES", "100")
    )

    AGENT_OFFLINE_AFTER_SECONDS = int(
        os.getenv("AGENT_OFFLINE_AFTER_SECONDS", "180")
    )

    # Integracje usług szkolnych są domyślnie wyłączone. Sam zapis
    # konfiguracji w panelu nie zmienia DNS, proxy, dźwięku ani kamer.
    WEB_FILTER_ENFORCEMENT_ENABLED = (
        os.getenv("WEB_FILTER_ENFORCEMENT_ENABLED", "false").lower() == "true"
    )
    RADIO_PLAYBACK_ENABLED = (
        os.getenv("RADIO_PLAYBACK_ENABLED", "false").lower() == "true"
    )
    RADIO_BELL_AUTOMATION_ENABLED = (
        os.getenv("RADIO_BELL_AUTOMATION_ENABLED", "false").lower() == "true"
    )
    RADIO_UPLOAD_MAX_BYTES = int(
        os.getenv("RADIO_UPLOAD_MAX_BYTES", str(50 * 1024 * 1024))
    )
    RADIO_PLAYER_BINARY = os.getenv("RADIO_PLAYER_BINARY", "mpv").strip() or "mpv"
    RADIO_AUDIO_DEVICE = os.getenv("RADIO_AUDIO_DEVICE", "auto").strip() or "auto"
    RADIO_TTS_BINARY = os.getenv("RADIO_TTS_BINARY", "espeak-ng").strip() or "espeak-ng"
    RADIO_TTS_VOICE = os.getenv("RADIO_TTS_VOICE", "pl").strip() or "pl"
    RADIO_TTS_SPEED = int(os.getenv("RADIO_TTS_SPEED", "165"))
    MONITORING_STREAMS_ENABLED = (
        os.getenv("MONITORING_STREAMS_ENABLED", "false").lower() == "true"
    )
    NETWORK_DRIVE_ENDPOINTS = _split_setting("NETWORK_DRIVE_ENDPOINTS", separator="|")
    NETWORK_DRIVE_SMB_TIMEOUT = float(os.getenv("NETWORK_DRIVE_SMB_TIMEOUT", "1.5"))
    # Oczekiwane powiązania udział=grupaAD, np. "Nauczyciele=G-Nauczyciele|Uczniowie=G-Uczniowie".
    NETWORK_DRIVE_SHARE_GROUPS = _split_setting("NETWORK_DRIVE_SHARE_GROUPS", separator="|")

    # Zapełnienie woluminów NAS przez SNMP tylko-do-odczytu (community string,
    # nie hasło administratora). Puste NETWORK_DRIVE_SNMP_COMMUNITY wyłącza
    # tę funkcję.
    NETWORK_DRIVE_SNMP_HOST = os.getenv("NETWORK_DRIVE_SNMP_HOST", "").strip()
    NETWORK_DRIVE_SNMP_COMMUNITY = os.getenv("NETWORK_DRIVE_SNMP_COMMUNITY", "")
    NETWORK_DRIVE_SNMP_PORT = int(os.getenv("NETWORK_DRIVE_SNMP_PORT", "161"))
    NETWORK_DRIVE_SNMP_TIMEOUT = float(os.getenv("NETWORK_DRIVE_SNMP_TIMEOUT", "3"))
    NETWORK_DRIVE_VOLUME_WARNING_PERCENT = float(
        os.getenv("NETWORK_DRIVE_VOLUME_WARNING_PERCENT", "85")
    )

    # Rejestratory NVR/DVR monitoringu, np. "Sekretariat=192.168.0.227|Portiernia=192.168.0.75".
    # Panel loguje tylko dostępność portu i otwarcie panelu w audycie — nigdy
    # nie przechowuje poświadczeń rejestratora ani obrazu z kamer.
    MONITORING_NVR_ENDPOINTS = _split_setting("MONITORING_NVR_ENDPOINTS", separator="|")
    MONITORING_NVR_TIMEOUT = float(os.getenv("MONITORING_NVR_TIMEOUT", "1.5"))

    # Pilotażowa migawka z jednej kamery (etap 4 z planu integracji): nazwa
    # musi odpowiadać jednemu z wpisów w MONITORING_NVR_ENDPOINTS. Konto
    # powinno być tylko-do-podglądu, nie administracyjne.
    MONITORING_SNAPSHOT_NVR_NAME = os.getenv("MONITORING_SNAPSHOT_NVR_NAME", "").strip()
    MONITORING_SNAPSHOT_USERNAME = os.getenv("MONITORING_SNAPSHOT_USERNAME", "")
    MONITORING_SNAPSHOT_PASSWORD = os.getenv("MONITORING_SNAPSHOT_PASSWORD", "")
    MONITORING_SNAPSHOT_CHANNEL = int(os.getenv("MONITORING_SNAPSHOT_CHANNEL", "1"))
    MONITORING_SNAPSHOT_TIMEOUT = float(os.getenv("MONITORING_SNAPSHOT_TIMEOUT", "5"))


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = (
        os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true"
    )


class TestingConfig(Config):
    TESTING = True
    DEBUG = False
    SECRET_KEY = "test-secret-key"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False

    # Testy nie mogą dziedziczyć tokenu z produkcyjnego pliku .env.
    SP2_API_TOKEN = "test-token"
    AGENT_API_TOKEN = "test-token"
    AGENT_ENROLLMENT_TOKEN = "test-token"


CONFIG_MAP = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}
