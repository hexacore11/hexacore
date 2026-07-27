from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import uuid
import json
import sqlite3

app = Flask(__name__)
DB_PATH = 'keys.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            expiry_date TEXT NOT NULL,
            max_devices INTEGER NOT NULL,
            revoked INTEGER DEFAULT 0,
            devices TEXT DEFAULT '[]'
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def get_key_data(key):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT expiry_date, max_devices, revoked, devices FROM keys WHERE key=?', (key,))
    row = c.fetchone()
    conn.close()
    if row:
        return {
            'expiry_date': row[0],
            'max_devices': row[1],
            'revoked': bool(row[2]),
            'devices': json.loads(row[3])
        }
    return None

def update_devices(key, devices):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE keys SET devices=? WHERE key=?', (json.dumps(devices), key))
    conn.commit()
    conn.close()

def is_key_valid(key_data):
    if key_data['revoked']:
        return False, 'revoked'
    expiry = datetime.fromisoformat(key_data['expiry_date'])
    if datetime.now() > expiry:
        return False, 'expired'
    return True, 'valid'

@app.route('/verify', methods=['GET'])
def verify():
    key = request.args.get('key')
    device_id = request.args.get('device_id')
    if not key or not device_id:
        return jsonify({'status': 'error', 'message': 'Missing key or device_id'}), 400

    key_data = get_key_data(key)
    if not key_data:
        return jsonify({'status': 'invalid', 'message': 'Key not found'})

    valid, status = is_key_valid(key_data)
    if not valid:
        return jsonify({'status': status, 'message': f'Key {status}'})

    devices = key_data['devices']
    max_dev = key_data['max_devices']

    if device_id not in devices:
        if len(devices) >= max_dev:
            return jsonify({'status': 'device_limit_exceeded', 'message': 'Maximum devices reached'})
        devices.append(device_id)
        update_devices(key, devices)

    return jsonify({
        'status': 'valid',
        'message': 'Key is valid',
        'expiry': key_data['expiry_date'],
        'max_devices': max_dev,
        'current_devices': len(devices)
    })

@app.route('/admin/generate', methods=['POST'])
def generate():
    data = request.get_json()
    days = data.get('expiry_days', 30)
    max_dev = data.get('max_devices', 1)
    new_key = str(uuid.uuid4()).replace('-', '')[:16]
    expiry = (datetime.now() + timedelta(days=days)).isoformat()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO keys (key, expiry_date, max_devices) VALUES (?,?,?)',
              (new_key, expiry, max_dev))
    conn.commit()
    conn.close()
    return jsonify({'key': new_key, 'expiry': expiry, 'max_devices': max_dev})

@app.route('/admin/revoke', methods=['POST'])
def revoke():
    data = request.get_json()
    key = data.get('key')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE keys SET revoked=1 WHERE key=?', (key,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'revoked', 'message': 'Key revoked'})

@app.route('/admin/extend', methods=['POST'])
def extend():
    data = request.get_json()
    key = data.get('key')
    extra_days = data.get('extra_days', 30)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT expiry_date FROM keys WHERE key=?', (key,))
    row = c.fetchone()
    if not row:
        return jsonify({'error': 'Key not found'}), 404
    new_expiry = (datetime.fromisoformat(row[0]) + timedelta(days=extra_days)).isoformat()
    c.execute('UPDATE keys SET expiry_date=? WHERE key=?', (new_expiry, key))
    conn.commit()
    conn.close()
    return jsonify({'new_expiry': new_expiry})

@app.route('/admin/list', methods=['GET'])
def list_keys():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT key, expiry_date, max_devices, revoked, devices FROM keys')
    rows = c.fetchall()
    conn.close()
    result = []
    for row in rows:
        result.append({
            'key': row[0],
            'expiry': row[1],
            'max_devices': row[2],
            'revoked': bool(row[3]),
            'devices': json.loads(row[4])
        })
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)