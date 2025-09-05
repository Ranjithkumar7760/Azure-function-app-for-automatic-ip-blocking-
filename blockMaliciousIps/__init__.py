
import datetime
import logging
import requests
import azure.functions as func

def main(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.utcnow().isoformat()
    logging.info("Timer function executed at %s", utc_timestamp)

    try:
        r = requests.get("https://httpbin.org/ip", timeout=5)
        logging.info(f"HTTP request successful: {r.json()}")
    except Exception as e:
        logging.error(f"Request failed: {e}")
