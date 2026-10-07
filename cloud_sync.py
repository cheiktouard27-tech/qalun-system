"""Persist the SQLite database to a private GitHub repository.

Free hosts (Render, HF, ...) wipe the local disk on every restart. When the
environment variables GITHUB_TOKEN and DATA_REPO (e.g. "user/qalun-data") are
set, this module:
  * restores data/qalun.sqlite3 from the repo on boot (if the local file is missing)
  * uploads a consistent snapshot a few seconds after every successful write request
Every upload is a git commit, so the repo doubles as a full backup history.
"""
import os, io, json, base64, threading, time, sqlite3, urllib.request, urllib.error

TOKEN = os.environ.get('GITHUB_TOKEN', '').strip()
REPO = os.environ.get('DATA_REPO', '').strip()
BRANCH = os.environ.get('DATA_BRANCH', 'main')
REMOTE_PATH = 'qalun.sqlite3'
API = 'https://api.github.com'
ENABLED = bool(TOKEN and REPO)
DEBOUNCE = int(os.environ.get('DATA_SYNC_DELAY', '15'))

_lock = threading.Lock()
_timer = None
_last_error = ''
_last_sync = 0.0

def _req(method, url, data=None, raw=False):
    headers = {'Authorization': 'Bearer ' + TOKEN, 'User-Agent': 'qalun-sync', 'X-GitHub-Api-Version': '2022-11-28'}
    headers['Accept'] = 'application/vnd.github.raw' if raw else 'application/vnd.github+json'
    body = None
    if data is not None:
        body = json.dumps(data).encode(); headers['Content-Type'] = 'application/json'
    r = urllib.request.Request(url, data=body, method=method, headers=headers)
    with urllib.request.urlopen(r, timeout=60) as resp:
        return resp.read()

def _contents_url():
    return f'{API}/repos/{REPO}/contents/{REMOTE_PATH}?ref={BRANCH}'

def _remote_sha():
    try:
        meta = json.loads(_req('GET', _contents_url()))
        return meta.get('sha')
    except urllib.error.HTTPError as e:
        if e.code == 404: return None
        raise

def restore(db_path):
    """Download the database from GitHub if there is no local copy yet."""
    global _last_error
    if not ENABLED or os.path.exists(db_path): return False
    try:
        blob = _req('GET', _contents_url(), raw=True)
        if blob[:16] != b'SQLite format 3\x00': raise ValueError('remote file is not a SQLite database')
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        with open(db_path, 'wb') as f: f.write(blob)
        print(f'[cloud_sync] restored {len(blob)} bytes from {REPO}', flush=True)
        return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print('[cloud_sync] no remote database yet, starting fresh', flush=True); return False
        _last_error = f'restore HTTP {e.code}'; print('[cloud_sync]', _last_error, flush=True)
    except Exception as e:
        _last_error = f'restore {e!r}'; print('[cloud_sync]', _last_error, flush=True)
    return False

def _snapshot(db_path):
    src = sqlite3.connect(db_path)
    try:
        src.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    except Exception: pass
    tmp = db_path + '.snapshot'
    dst = sqlite3.connect(tmp)
    src.backup(dst)          # consistent copy even while the app is writing
    dst.close(); src.close()
    with open(tmp, 'rb') as f: data = f.read()
    try: os.remove(tmp)
    except OSError: pass
    return data

def upload(db_path):
    global _last_error, _last_sync
    if not ENABLED: return False
    with _lock:
        try:
            data = _snapshot(db_path)
            payload = {'message': 'qalun backup ' + time.strftime('%Y-%m-%d %H:%M:%S'),
                       'content': base64.b64encode(data).decode(), 'branch': BRANCH}
            sha = _remote_sha()
            if sha: payload['sha'] = sha
            _req('PUT', f'{API}/repos/{REPO}/contents/{REMOTE_PATH}', payload)
            _last_sync = time.time(); _last_error = ''
            print(f'[cloud_sync] uploaded {len(data)} bytes', flush=True)
            return True
        except urllib.error.HTTPError as e:
            if e.code == 409:  # sha race: retry once with fresh sha
                try:
                    payload['sha'] = _remote_sha(); _req('PUT', f'{API}/repos/{REPO}/contents/{REMOTE_PATH}', payload)
                    _last_sync = time.time(); _last_error = ''; return True
                except Exception as e2: _last_error = f'upload retry {e2!r}'
            else: _last_error = f'upload HTTP {e.code}'
        except Exception as e:
            _last_error = f'upload {e!r}'
        print('[cloud_sync]', _last_error, flush=True)
        return False

def schedule(db_path):
    """Debounced upload: many writes in a row -> one commit."""
    global _timer
    if not ENABLED: return
    with _lock:
        if _timer: _timer.cancel()
        _timer = threading.Timer(DEBOUNCE, upload, args=(db_path,)); _timer.daemon = True; _timer.start()

def status():
    return {'enabled': ENABLED, 'repo': REPO if ENABLED else None, 'last_sync': _last_sync, 'last_error': _last_error}
