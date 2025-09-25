from flask import Flask, request, render_template, abort, make_response, session, redirect, url_for
from collections import deque
import threading
import time
import random

app = Flask(__name__)
app.secret_key = 'your_secret_key_here_change_this_in_production'

# CONFIG
MAX_REQUESTS = 10       # max requests
WINDOW_SECONDS = 60     # per WINDOW_SECONDS
BLOCK_STATUS = 429
BLOCK_MESSAGE = 'Too many requests — limit is {} requests per {} seconds.'.format(MAX_REQUESTS, WINDOW_SECONDS)

# In-memory store: {ip: deque([timestamp, ...])}
_requests = {}
_lock = threading.Lock()


def _get_client_ip():
    # If behind a reverse proxy, ensure X-Forwarded-For is set correctly
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        # take the left-most (original client) IP
        return xff.split(',')[0].strip()
    return request.remote_addr or 'unknown'


@app.before_request
def check_verification():
    # Doğrulama sayfası ve statik dosyalar için rate limiting'i atla
    if request.path == '/verify' or request.path == '/verify-success' or request.path.startswith('/static'):
        return

    # Eğer kullanıcı doğrulanmamışsa, doğrulama sayfasına yönlendir
    if not session.get('verified'):
        return redirect('/verify')


@app.before_request
def rate_limit():
    # Doğrulama sayfası ve statik dosyalar için rate limiting'i atla
    if request.path == '/verify' or request.path == '/verify-success' or request.path.startswith('/static'):
        return

    client_ip = _get_client_ip()
    now = time.time()
    window_start = now - WINDOW_SECONDS

    with _lock:
        dq = _requests.get(client_ip)
        if dq is None:
            dq = deque()
            _requests[client_ip] = dq

        # purge old timestamps
        while dq and dq[0] < window_start:
            dq.popleft()

        if len(dq) >= MAX_REQUESTS:
            # exceed limit
            resp = make_response(BLOCK_MESSAGE, BLOCK_STATUS)
            resp.headers['Retry-After'] = str(WINDOW_SECONDS)
            return resp

        dq.append(now)


@app.route('/')
def index():
    # Ana sayfa - sadece doğrulanmış kullanıcılar erişebilir
    if not session.get('verified'):
        return redirect('/verify')

    return render_template('index3.html')


@app.route('/verify')
def verification_page():
    # Doğrulama sayfası - eğer zaten doğrulanmışsa ana sayfaya yönlendir
    if session.get('verified'):
        return redirect('/')
    return render_template('robot_dogrulama.html')


@app.route('/verify-success')
def verify_success():
    # Doğrulama başarılı endpoint'i - session'ı ayarla ve ana sayfaya yönlendir
    session['verified'] = True
    return redirect('/')


@app.route('/health')
def health():
    return 'ok'


if __name__ == '__main__':
    # For production, run behind a proper WSGI server (gunicorn/uvicorn) and
    # preferably use a shared rate-limiter (Redis) when you have multiple workers.
    # For quick testing:
    app.run(host='0.0.0.0', port=5000, debug=True)
