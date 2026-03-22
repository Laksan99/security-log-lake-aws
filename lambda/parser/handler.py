import json
import csv
import io
import boto3
import logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")

# ── Constantes ─────────────────────────────────────────────
PROCESSED_PREFIX = "processed"

# ── Campos esperados por tipo de log ───────────────────────
FIREWALL_FIELDS = [
    "timestamp", "device_id", "action", "src_ip", "dst_ip",
    "src_port", "dst_port", "protocol", "bytes_sent", "bytes_received",
    "duration_sec", "severity", "policy_name", "country_src", "country_dst"
]

VPN_FIELDS = [
    "timestamp", "device_id", "event_type", "user", "src_ip",
    "vpn_gateway", "auth_method", "session_duration_sec",
    "bytes_transferred", "status", "failure_reason"
]

VPC_FLOW_FIELDS = [
    "timestamp", "account_id", "interface_id", "src_ip", "dst_ip",
    "src_port", "dst_port", "protocol", "packets", "bytes",
    "action", "log_status"
]

SCHEMA_MAP = {
    "firewall": FIREWALL_FIELDS,
    "vpn": VPN_FIELDS,
    "vpc-flow": VPC_FLOW_FIELDS,
}

# ── Helpers ────────────────────────────────────────────────
def detect_source(key: str) -> str | None:
    """Detecta el tipo de log desde el prefijo del key de S3."""
    for source in SCHEMA_MAP:
        if f"/{source}/" in key or key.startswith(f"raw/{source}"):
            return source
    return None

def normalize_timestamp(ts: str) -> str:
    """Normaliza el timestamp a formato ISO 8601."""
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d/%m/%Y %H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt).strftime("%Y-%m-%dT%H:%M:%S")
        except ValueError:
            continue
    return ts  # Si no parsea, lo deja como está

def normalize_action(action: str, source: str) -> str:
    """Normaliza los valores de action/status a un vocabulario común."""
    mapping = {
        "ALLOW": "ALLOW", "ACCEPT": "ALLOW",
        "DENY": "DENY", "REJECT": "DENY", "DROP": "DENY",
        "RESET": "RESET",
        "SUCCESS": "SUCCESS", "AUTH_SUCCESS": "SUCCESS",
        "FAIL": "FAIL", "AUTH_FAIL": "FAIL",
        "SESSION_START": "SESSION_START",
        "SESSION_END": "SESSION_END",
    }
    return mapping.get(action.upper(), action.upper())

def validate_row(row: dict, fields: list, row_num: int) -> tuple[dict, list]:
    """Valida que el row tenga todos los campos esperados."""
    issues = []
    for field in fields:
        if field not in row or row[field] == "":
            issues.append(f"row {row_num}: missing field '{field}'")
            row[field] = None
    return row, issues

def parse_csv(content: str, source: str) -> tuple[list, list]:
    """Parsea el CSV y normaliza los registros."""
    fields = SCHEMA_MAP[source]
    reader = csv.DictReader(io.StringIO(content))
    records = []
    all_issues = []

    for i, row in enumerate(reader, start=1):
        row, issues = validate_row(dict(row), fields, i)
        all_issues.extend(issues)

        # Normalizar timestamp
        if row.get("timestamp"):
            row["timestamp"] = normalize_timestamp(row["timestamp"])

        # Normalizar action según la fuente
        action_field = {
            "firewall": "action",
            "vpn": "status",
            "vpc-flow": "action"
        }.get(source)

        if action_field and row.get(action_field):
            row[action_field] = normalize_action(row[action_field], source)

        # Agregar metadata de procesamiento
        row["_source"] = source
        row["_processed_at"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        row["_has_issues"] = len(issues) > 0

        records.append(row)

    return records, all_issues

def records_to_csv(records: list) -> str:
    """Convierte lista de dicts a string CSV."""
    if not records:
        return ""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=records[0].keys())
    writer.writeheader()
    writer.writerows(records)
    return output.getvalue()

# ── Handler principal ──────────────────────────────────────
def lambda_handler(event, context):
    for record in event["Records"]:
        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]

        logger.info(f"Processing: s3://{bucket}/{key}")

        # Detectar tipo de log
        source = detect_source(key)
        if not source:
            logger.warning(f"Unknown log source for key: {key} — skipping")
            continue

        # Leer archivo raw desde S3
        response = s3.get_object(Bucket=bucket, Key=key)
        content = response["Body"].read().decode("utf-8")

        # Parsear y normalizar
        records, issues = parse_csv(content, source)

        if issues:
            logger.warning(f"Data quality issues in {key}: {len(issues)} problems")
            for issue in issues[:10]:  # Log solo los primeros 10
                logger.warning(f"  → {issue}")

        # Construir key de destino en processed/
        filename = key.split("/")[-1]
        processed_key = key.replace("raw/", "processed/", 1)

        # Escribir CSV procesado en S3
        processed_csv = records_to_csv(records)
        s3.put_object(
            Bucket=bucket,
            Key=processed_key,
            Body=processed_csv.encode("utf-8"),
            ContentType="text/csv",
            Metadata={
                "source": source,
                "record_count": str(len(records)),
                "issues_count": str(len(issues)),
            }
        )

        logger.info(f"✅ Processed {len(records)} records → s3://{bucket}/{processed_key}")

    return {
        "statusCode": 200,
        "body": json.dumps({"message": "Processing complete"})
    }