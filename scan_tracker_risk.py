import json
import re
from collections import defaultdict

# ===== LOAD JSON =====
with open("tracker.json", "r", encoding="utf-8") as f:
    data = json.load(f)

illegal_pattern = re.compile(r"[^a-zA-Z0-9\-_:]")

results = []
tracker_count = defaultdict(lambda: defaultdict(int))

# ===== COUNT DUPLICATES =====
for service in data["serviceMappings"]:
    dps = service["dpsId"]
    for t in service["trackers"]:
        tracker_count[dps][t["trackerName"]] += 1

# ===== ANALYZE TRACKERS =====
for service in data["serviceMappings"]:
    dps = service["dpsId"]
    for t in service["trackers"]:
        name = t["trackerName"]
        storage = t["storageType"]
        provider = t["providerUrl"]
        expiry = t["expiry"]

        issues = []
        severity = "OK"

        # Duplicate check
        if tracker_count[dps][name] > 1:
            issues.append("DUPLICATE_TRACKER")
            severity = "POTENTIAL_BUG"

        # Illegal character check
        if illegal_pattern.search(name):
            issues.append("ILLEGAL_CHARS")
            severity = "POTENTIAL_BUG"

        # Cross-domain mismatch
        if provider.startswith("http"):
            domain = provider.replace("https://", "").replace("http://", "")
        else:
            domain = provider

        if "." not in domain:
            issues.append("INVALID_PROVIDER_DOMAIN")
            severity = "POTENTIAL_BUG"

        # IndexedDB = higher risk
        if storage == "IndexedDB":
            issues.append("INDEXEDDB_PERSISTENT")
            severity = "CRITICAL"

        # Cookie expiry sanity
        if storage == "HTTP Document Cookie" and expiry == "session":
            issues.append("SESSION_COOKIE")
        
        results.append({
            "dpsId": dps,
            "trackerName": name,
            "storageType": storage,
            "expiry": expiry,
            "provider": provider,
            "severity": severity,
            "issues": ",".join(issues) if issues else "NONE"
        })

# ===== OUTPUT =====
print("\n=== TRACKER RISK REPORT ===\n")
for r in results:
    print(
        f"[{r['severity']}] "
        f"{r['trackerName']} | {r['storageType']} | {r['provider']} | {r['issues']}"
    )
