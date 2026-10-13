from app.nas_snmp import HR_STORAGE_FIXED_DISK, VolumeUsage, aggregate_storage_columns


def test_aggregate_storage_columns_filters_to_fixed_disks_and_computes_percent():
    types = {
        "1": "1.3.6.1.2.1.25.2.1.2",  # hrStorageRam — powinno zostać pominięte
        "2": HR_STORAGE_FIXED_DISK,
        "3": HR_STORAGE_FIXED_DISK,
    }
    descrs = {"2": "/share/CACHEDEV1_DATA", "3": "/share/CACHEDEV2_DATA"}
    units = {"2": "4096", "3": "4096"}
    sizes = {"2": "1000000", "3": "500000"}
    useds = {"2": "800000", "3": "50000"}

    volumes = aggregate_storage_columns(
        types=types, descrs=descrs, units=units, sizes=sizes, useds=useds
    )

    assert volumes == [
        VolumeUsage(
            label="/share/CACHEDEV1_DATA",
            total_bytes=1000000 * 4096,
            used_bytes=800000 * 4096,
            percent_used=80.0,
        ),
        VolumeUsage(
            label="/share/CACHEDEV2_DATA",
            total_bytes=500000 * 4096,
            used_bytes=50000 * 4096,
            percent_used=10.0,
        ),
    ]


def test_aggregate_storage_columns_skips_incomplete_rows():
    types = {"1": HR_STORAGE_FIXED_DISK, "2": HR_STORAGE_FIXED_DISK}
    descrs = {"1": "/share/CACHEDEV1_DATA"}
    units = {"1": "4096"}
    sizes = {"1": "1000"}
    useds = {"1": "500"}  # brak danych dla indeksu "2"

    volumes = aggregate_storage_columns(
        types=types, descrs=descrs, units=units, sizes=sizes, useds=useds
    )

    assert len(volumes) == 1
    assert volumes[0].label == "/share/CACHEDEV1_DATA"


def test_aggregate_storage_columns_skips_zero_size():
    types = {"1": HR_STORAGE_FIXED_DISK}
    descrs = {"1": "/share/CACHEDEV1_DATA"}
    units = {"1": "4096"}
    sizes = {"1": "0"}
    useds = {"1": "0"}

    assert aggregate_storage_columns(
        types=types, descrs=descrs, units=units, sizes=sizes, useds=useds
    ) == []


def test_aggregate_storage_columns_ignores_snapshots_and_system_mounts():
    # Odkryte na żywo na 192.168.0.203: hrStorageFixedDisk na QNAP obejmuje
    # też /tmp, /usr, /home i osobny wpis dla KAŻDEJ migawki
    # (/mnt/snapshot/1/100xx to ten sam wolumin widziany wielokrotnie).
    # Tylko /share/CACHEDEV<N>_DATA to prawdziwe, przyrostowe woluminy.
    types = {str(i): HR_STORAGE_FIXED_DISK for i in range(1, 6)}
    descrs = {
        "1": "/tmp",
        "2": "/usr",
        "3": "/mnt/snapshot/1/10001",
        "4": "/share/CACHEDEV1_DATA",
        "5": "/share/CACHEDEV2_DATA",
    }
    units = {str(i): "4096" for i in range(1, 6)}
    sizes = {str(i): "1000000" for i in range(1, 6)}
    useds = {str(i): "500000" for i in range(1, 6)}

    volumes = aggregate_storage_columns(
        types=types, descrs=descrs, units=units, sizes=sizes, useds=useds
    )

    assert [v.label for v in volumes] == [
        "/share/CACHEDEV1_DATA",
        "/share/CACHEDEV2_DATA",
    ]


def test_aggregate_storage_columns_matches_live_qnap_output():
    # Podzbiór realnej odpowiedzi SNMP z produkcyjnego QNAP (NAS731BD9),
    # zweryfikowany na żywo 2026-08-21.
    types = {"a": HR_STORAGE_FIXED_DISK, "b": HR_STORAGE_FIXED_DISK, "c": HR_STORAGE_FIXED_DISK}
    descrs = {
        "a": "/share/CACHEDEV1_DATA",
        "b": "/share/CACHEDEV2_DATA",
        "c": "/share/CACHEDEV3_DATA",
    }
    units = {"a": "1", "b": "1", "c": "1"}
    sizes = {"a": "2485948305408", "b": "15709999513600", "c": "2475029192704"}
    useds = {"a": "60844646400", "b": "20930560", "c": "809635840"}

    volumes = aggregate_storage_columns(
        types=types, descrs=descrs, units=units, sizes=sizes, useds=useds
    )

    assert [v.label for v in volumes] == [
        "/share/CACHEDEV1_DATA",
        "/share/CACHEDEV2_DATA",
        "/share/CACHEDEV3_DATA",
    ]
    assert volumes[0].percent_used == 2.4
    assert volumes[1].percent_used == 0.0
    assert volumes[2].percent_used == 0.0
