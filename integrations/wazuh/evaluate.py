"""Collect one fresh logtest session through Wazuh 4.14.7's installed framework."""

import hashlib
import json
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


def evaluate(request):
    """Use the actual analysis engine and preserve structured per-event output."""

    # The embedded interpreter already selects the installed Wazuh package.
    # The top-level framework directory can contain an incomplete package copy.
    from wazuh.core.common import LOGTEST_SOCKET
    from wazuh.core.logtest import send_logtest_msg

    deadline = time.monotonic() + 20
    while not Path(LOGTEST_SOCKET).exists():
        if time.monotonic() >= deadline:
            raise ValueError("the manager's logtest socket is not ready")
        time.sleep(0.5)

    info = subprocess.run(
        ["/var/ossec/bin/wazuh-control", "info"],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    ).stdout
    version = re.search(r'WAZUH_VERSION="?v?([0-9.]+)', info)
    if version is None or version.group(1) != request["expected_version"]:
        raise ValueError("running manager version does not match the pinned evaluator")
    for path, expected in request["runtime_file_sha256"].items():
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected:
            raise ValueError(f"manager rule file differs from the case input: {path}")

    token = None
    results = []
    started = time.monotonic()
    try:
        for item in request["events"]:
            parameters = {
                "event": json.dumps(
                    item["event"], separators=(",", ":"), sort_keys=True
                ),
                "log_format": "syslog",
                "location": "EventChannel",
            }
            if token is not None:
                parameters["token"] = token
            response = send_logtest_msg("log_processing", parameters)
            if response.get("error") != 0:
                raise ValueError(f"Wazuh rejected a test event: {response}")
            data = response["data"]
            returned_token = data.get("token")
            if not returned_token or (token is not None and returned_token != token):
                raise ValueError("Wazuh did not preserve the fresh evaluation session")
            token = returned_token
            if data.get("codemsg", 0) != 0 or not isinstance(data.get("output"), dict):
                raise ValueError(f"Wazuh could not evaluate the test event: {data}")
            if time.monotonic() - started >= 60:
                raise ValueError("evaluation exceeded the 60-second ingestion window")
            results.append(
                {
                    "event_instance_id": item["event_instance_id"],
                    "processed_at": datetime.now().astimezone().isoformat(),
                    "would_alert": data["alert"],
                    "output": data["output"],
                }
            )
    finally:
        if token is not None:
            closed = send_logtest_msg("remove_session", {"token": token})
            if closed.get("error") != 0:
                raise ValueError("Wazuh could not close the evaluation session")
    return {"manager_version": version.group(1), "results": results}


if __name__ == "__main__":
    try:
        print(json.dumps(evaluate(json.load(sys.stdin))))
    except Exception as error:
        print(f"Wazuh evaluation failed: {error}", file=sys.stderr)
        sys.exit(1)
