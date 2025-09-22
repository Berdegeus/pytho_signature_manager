import json,urllib.request,urllib.error
base = 'http://127.0.0.1:8080'

def get(url, headers=None):
    req = urllib.request.Request(url, method='GET', headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            body = r.read().decode()
            print('GET', url, r.status, body)
            return r.status, body
    except urllib.error.HTTPError as e:
        print('GET ERR', url, e.code, e.read().decode())
    except Exception as e:
        print('GET ERR', url, str(e))

def post(url, payload, headers=None):
    data = json.dumps(payload).encode()
    h = {'Content-Type':'application/json'}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, method='POST', headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            body = r.read().decode()
            print('POST', url, r.status, body)
            return r.status, body
    except urllib.error.HTTPError as e:
        print('POST ERR', url, e.code, e.read().decode())
    except Exception as e:
        print('POST ERR', url, str(e))

# Health
get(base + '/health')

# Login
st, body = post(base + '/login', {"email":"alice@example.com","password":"password123"})
if st == 200:
    token = json.loads(body)['token']
    # Status com token
    get(base + '/user/1/status', headers={"Authorization": f"Bearer {token}"})

