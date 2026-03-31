import json   # used to read JSON data
import time   # used for continuous monitoring

# path to Suricata eve.json (WSL → Windows access)
LOG_FILE = r"\\wsl$\Ubuntu\var\log\suricata\eve.json"


def read_alerts():
    alerts = []   # list to store alerts

    with open(LOG_FILE, "r") as file:   # open log file
        for line in file:   # read each line

            try:
                data = json.loads(line)   # convert JSON string to dict
            except:
                continue   # skip invalid lines

            # check if event is an alert
            if data.get("event_type") == "alert":

                signature = data.get("alert", {}).get("signature")
                severity = data.get("alert", {}).get("severity")

                # ❌ ignore low-value / noisy alerts
                if "INFO" in str(signature):
                    continue

                # ✅ keep only important alerts (1 = high, 2 = medium)
                if severity is not None and severity <= 2:

                    alert_info = {
                        "src_ip": data.get("src_ip"),
                        "dest_ip": data.get("dest_ip"),
                        "signature": signature,
                        "severity": severity,
                    }

                    alerts.append(alert_info)

    return alerts


if __name__ == "__main__":

    print("🚀 Starting Suricata Alert Monitor...\n")

    while True:
        alerts = read_alerts()

        if alerts:
            print("⚠️ Alerts detected:\n")
            for alert in alerts:
                print(alert)
        else:
            print("No important alerts...")

        print("\n---- refreshing ----\n")

        time.sleep(5)   # refresh every 5 seconds