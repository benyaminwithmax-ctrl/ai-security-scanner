import os, sys, json
from flask import Flask, render_template, jsonify
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

app = Flask(__name__)
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output")

def load_siem_logs():
    log_file = os.path.join(OUTPUT_DIR, "siem_logs.ndjson")
    events = []
    if os.path.exists(log_file):
        with open(log_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except:
                        pass
    return events

def get_stats(events):
    total = len(events)
    critical = sum(1 for e in events if e.get("vulnerability",{}).get("severity") == "CRITICAL")
    high = sum(1 for e in events if e.get("vulnerability",{}).get("severity") == "HIGH")
    medium = sum(1 for e in events if e.get("vulnerability",{}).get("severity") == "MEDIUM")
    low = sum(1 for e in events if e.get("vulnerability",{}).get("severity") == "LOW")
    categories = {}
    for e in events:
        cat = e.get("vulnerability",{}).get("category","unknown")
        categories[cat] = categories.get(cat, 0) + 1
    mitre = {}
    for e in events:
        tid = e.get("threat",{}).get("technique",{}).get("id","unknown")
        mitre[tid] = mitre.get(tid, 0) + 1
    return {"total": total, "critical": critical, "high": high, "medium": medium, "low": low, "categories": categories, "mitre": mitre}

@app.route("/")
def dashboard():
    events = load_siem_logs()
    stats = get_stats(events)
    return render_template("dashboard.html", stats=stats, events=events[:50])

@app.route("/api/stats")
def api_stats():
    events = load_siem_logs()
    return jsonify(get_stats(events))

@app.route("/api/events")
def api_events():
    events = load_siem_logs()
    return jsonify(events[:100])

@app.route("/api/report")
def api_report():
    reports = [f for f in os.listdir(OUTPUT_DIR) if f.endswith(".txt")]
    if not reports:
        return jsonify({"error": "No reports found"})
    latest = sorted(reports)[-1]
    with open(os.path.join(OUTPUT_DIR, latest)) as f:
        content = f.read()
    return jsonify({"filename": latest, "content": content})

if __name__ == "__main__":
    port = int(os.getenv("FLASK_PORT", 5000))
    print(f"Dashboard running on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
