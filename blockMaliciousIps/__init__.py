import os, datetime, logging, requests, ipaddress
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
from azure.mgmt.web import WebSiteManagementClient
import azure.functions as func

# Env
WORKSPACE_ID = os.environ["WORKSPACE_ID"]
SUBSCRIPTION_ID = os.environ["SUBSCRIPTION_ID"]
RESOURCE_GROUP = os.environ["RESOURCE_GROUP"]
APP_SERVICE_NAME = os.environ["APP_SERVICE_NAME"]
CS_HOST = os.environ.get("CS_HOST", "ip-blocking-function.azurewebsites.net")
TIME_RANGE_HOURS = int(os.environ.get("TIME_RANGE_HOURS", "1"))
ABUSE_IPDB_KEY = os.environ["ABUSE_IPDB_KEY"]
ABUSE_SCORE_THRESHOLD = int(os.environ.get("ABUSE_SCORE_THRESHOLD", "50"))

credential = DefaultAzureCredential()
log_client = LogsQueryClient(credential)
web_client = WebSiteManagementClient(credential, SUBSCRIPTION_ID)

KQL = f"""
AppServiceHTTPLogs
| where TimeGenerated > ago({{TIME}}h)
| where CsHost == "{CS_HOST}"
| summarize Hits = count() by ClientIP
| where isnotempty(ClientIP)
""".replace("{TIME}", str(TIME_RANGE_HOURS))

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSE_HEADERS = {"Accept": "application/json", "Key": ABUSE_IPDB_KEY}

def _cidr(ip: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return f"{ip}/32" if ip_obj.version == 4 else f"{ip}/128"
    except ValueError:
        return None

def _is_public_ipv4(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.version == 4 and ip_obj.is_global
    except ValueError:
        return False

def get_candidate_ips():
    resp = log_client.query_workspace(WORKSPACE_ID, KQL, timespan=datetime.timedelta(hours=TIME_RANGE_HOURS))
    if not resp.tables:
        return []
    ips = [row[0] for row in resp.tables[0].rows if row and row[0]]
    return [ip for ip in ips if _is_public_ipv4(ip)]

def abuse_score(ip: str) -> int:
    try:
        r = requests.get(ABUSE_URL, headers=ABUSE_HEADERS, params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=10)
        r.raise_for_status()
        return int(r.json()["data"].get("abuseConfidenceScore", 0))
    except Exception as e:
        logging.warning(f"AbuseIPDB check failed for {ip}: {e}")
        return 0

def restriction_exists(restrictions, ip_cidr: str) -> bool:
    for r in restrictions:
        ip_addr = getattr(r, "ip_address", None) or (r.get("ip_address") if isinstance(r, dict) else None)
        if ip_addr == ip_cidr:
            return True
    return False

def add_block_rule(ip: str):
    ip_cidr = _cidr(ip)
    if not ip_cidr:
        return
    cfg = web_client.web_apps.get_configuration(RESOURCE_GROUP, APP_SERVICE_NAME)
    restrictions = list(cfg.ip_security_restrictions or [])

    if restriction_exists(restrictions, ip_cidr):
        logging.info(f"Rule already exists for {ip_cidr}")
        return

    used = set()
    for r in restrictions:
        pr = getattr(r, "priority", None) or (r.get("priority") if isinstance(r, dict) else None)
        if isinstance(pr, int):
            used.add(pr)
    prio = 200
    while prio in used:
        prio += 1

    rule = {
        "ip_address": ip_cidr,
        "action": "Deny",
        "priority": prio,
        "name": f"block_{ip}",
        "description": f"Auto-blocked by Function on {datetime.datetime.utcnow().isoformat()}Z"
    }

    restrictions.append(rule)
    web_client.web_apps.update_configuration(RESOURCE_GROUP, APP_SERVICE_NAME, {"ip_security_restrictions": restrictions})
    logging.info(f"Added deny rule for {ip_cidr} at priority {prio}")

def main(mytimer: func.TimerRequest) -> None:
    logging.info("Function start: scanning IPs")
    ips = get_candidate_ips()
    logging.info(f"Candidate IPs: {ips}")

    for ip in ips:
        score = abuse_score(ip)
        if score >= ABUSE_SCORE_THRESHOLD:
            logging.info(f"Malicious IP {ip} with score {score} – blocking")
            add_block_rule(ip)
        else:
            logging.info(f"Benign or unknown IP {ip} with score {score}")

    logging.info("Function completed")
