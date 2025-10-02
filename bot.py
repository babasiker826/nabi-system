from flask import Flask, request, render_template, session, redirect
import requests
import time
from collections import deque
import threading

app = Flask(__name__)
app.secret_key = 'change_this_to_a_secure_random_value_in_production'

# GOOGLE reCAPTCHA v2 KEY’LERİ
SITE_KEY = "6LfNH9srAAAAADykYLJ0UujXd2AsYEUTDcZ-LegN"       # HTML’de görünecek
SECRET_KEY = "6LfNH9srAAAAAHDqEC81oq4vCQTqRl0bDUriU2HN"   # backend doğrulama

# RATE LIMIT CONFIG
MAX_REQUESTS = 10
WINDOW_SECONDS = 60
BLOCK_STATUS = 429
BLOCK_MESSAGE = f"Too many requests — limit is {MAX_REQUESTS} requests per {WINDOW_SECONDS} seconds."

_requests = {}
_lock = threading.Lock()

def _get_client_ip():
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or 'unknown'

@app.before_request
def rate_limit_and_verify():
    if request.path in ['/verify', '/verify-success'] or request.path.startswith('/static'):
        return

    # Rate limiting
    client_ip = _get_client_ip()
    now = time.time()
    window_start = now - WINDOW_SECONDS
    with _lock:
        dq = _requests.get(client_ip, deque())
        while dq and dq[0] < window_start:
            dq.popleft()
        if len(dq) >= MAX_REQUESTS:
            resp = app.response_class(BLOCK_MESSAGE, status=BLOCK_STATUS)
            resp.headers['Retry-After'] = str(WINDOW_SECONDS)
            return resp
        dq.append(now)
        _requests[client_ip] = dq

    # CAPTCHA doğrulaması yapılmamışsa verify sayfasına yönlendir
    if not session.get('verified'):
        return redirect('/verify')

@app.route('/')
def index():
    return render_template('index3.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    error = None
    if request.method == 'POST':
        token = request.form.get('g-recaptcha-response')
        if not token:
            error = "Lütfen reCAPTCHA kutusunu işaretleyin."
            return render_template('robot_dogrulama.html', site_key=SITE_KEY, error=error)

        payload = {'secret': SECRET_KEY, 'response': token, 'remoteip': request.remote_addr}
        try:
            r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload, timeout=5)
            result = r.json()
        except Exception as e:
            error = "Doğrulama sırasında hata oluştu."
            return render_template('robot_dogrulama.html', site_key=SITE_KEY, error=error)

        if result.get("success"):
            session['verified'] = True
            return redirect('/')
        else:
            error = "Doğrulama başarısız. Tekrar deneyin."
            return render_template('robot_dogrulama.html', site_key=SITE_KEY, error=error)

    return render_template('robot_dogrulama.html', site_key=SITE_KEY, error=error)

@app.route('/health')
def health():
    return 'ok'

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
