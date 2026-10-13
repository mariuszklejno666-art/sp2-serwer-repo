from __future__ import annotations


def parse_query_user_output(output: str) -> dict | None:
    """Parsuje wyjście polecenia `query user`, zwracając aktywną sesję konsoli.

    Zwraca {"username": str, "session_id": int, "session_name": str} dla
    pierwszej sesji będącej lokalną konsolą (fizyczny pulpit) albo w stanie
    Active — to ta sesja, którą można podejrzeć/przejąć przez
    `mstsc /shadow`. Zwraca None, gdy nikt nie jest zalogowany albo
    wyjście jest nieczytelne.

    Zweryfikowane na żywo wobec prawdziwego `query user`:
    " USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME"
    ">sp2                   console             1  Active      none   21.08.2026 08:29"
    `query.exe` bywa zwraca kod wyjścia != 0 nawet przy poprawnym wyniku,
    więc ten parser celowo nie zależy od returncode — tylko od treści.
    """
    lines = output.splitlines()
    if len(lines) < 2:
        return None

    for raw_line in lines[1:]:
        line = raw_line[1:] if raw_line.startswith(">") else raw_line
        parts = line.split()
        if len(parts) < 3:
            continue
        username = parts[0]

        session_id = None
        session_name = None
        state_index = None
        for index, part in enumerate(parts[1:], start=1):
            if part.isdigit():
                session_id = int(part)
                if index > 1:
                    session_name = parts[1]
                state_index = index + 1
                break
        if session_id is None:
            continue

        state = parts[state_index] if state_index is not None and state_index < len(parts) else ""
        is_console = bool(session_name) and session_name.lower() == "console"
        is_active = state.lower() == "active"
        if is_console or is_active:
            return {
                "username": username,
                "session_id": session_id,
                "session_name": session_name or "",
            }
    return None
