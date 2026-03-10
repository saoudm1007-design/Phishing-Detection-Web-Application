import re, math, os, time, socket, json, uuid, sqlite3
from datetime import datetime
from urllib.parse import urlparse
import requests
import requests.packages.urllib3.util.connection as urllib3_cn
from flask import Flask, render_template, request, jsonify, abort
from dotenv import load_dotenv
import tldextract

load_dotenv('/var/www/phishing-detection/.env')
app = Flask(__name__)

VT_API_KEY    = os.getenv('VT_API_KEY')
GOOGLE_SB_KEY = os.getenv('GOOGLE_SB_KEY')
VT_HEADERS    = {'x-apikey': VT_API_KEY}
DB_PATH       = '/var/www/phishing-detection/results.db'

# Force IPv4 for all outbound requests
urllib3_cn.allowed_gai_family = lambda: socket.AF_INET

SUSPICIOUS_KEYWORDS = [
    'login','signin','verify','update','secure','account','banking',
    'paypal','ebay','amazon','apple','google','microsoft','netflix',
    'password','credential','confirm','suspend','urgent','alert',
    'free','winner','prize','click','limited','offer','wallet',
    'crypto','bitcoin','invest','bonus'
]
TRUSTED_TLDS    = {'.com','.org','.net','.edu','.gov','.io','.co'}
SUSPICIOUS_TLDS = {'.xyz','.tk','.ml','.ga','.cf','.gq','.pw','.top',
                   '.click','.download','.link','.online','.site','.live'}

# ── Database ──────────────────────────────────────────────────────────────────
def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute('''CREATE TABLE IF NOT EXISTS results
                   (id TEXT PRIMARY KEY, url TEXT, data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    con.commit(); con.close()

def save_result(result_id, data):
    con = sqlite3.connect(DB_PATH)
    con.execute('INSERT OR REPLACE INTO results (id, url, data) VALUES (?,?,?)',
                (result_id, data.get('url',''), json.dumps(data)))
    con.commit(); con.close()

def load_result(result_id):
    con = sqlite3.connect(DB_PATH)
    row = con.execute('SELECT data FROM results WHERE id=?', (result_id,)).fetchone()
    con.close()
    return json.loads(row[0]) if row else None

init_db()

# ── Helpers ───────────────────────────────────────────────────────────────────
def entropy(s):
    if not s: return 0
    prob = [float(s.count(c))/len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def whois_age(domain):
    try:
        import whois
        w = whois.whois(domain)
        cd = w.creation_date
        if isinstance(cd, list): cd = cd[0]
        if cd:
            age = (datetime.now() - cd).days
            return age
    except: pass
    return None

def extract_features(url):
    parsed = urlparse(url if url.startswith('http') else 'http://'+url)
    ext    = tldextract.extract(url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    path   = parsed.path
    f = {}
    f['url_length']    = len(url)
    f['domain_length'] = len(domain)
    f['dot_count']     = url.count('.')
    f['hyphen_count']  = domain.count('-')
    f['digit_count']   = sum(c.isdigit() for c in domain)
    f['special_chars'] = len(re.findall(r'[@!$%^&*()+=\[\]{}|<>]', url))
    f['is_ip']         = 1 if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', domain) else 0
    f['has_https']     = 1 if parsed.scheme == 'https' else 0
    f['subdomain_count'] = len(ext.subdomain.split('.')) if ext.subdomain else 0
    f['path_depth']    = len([p for p in path.split('/') if p])
    url_lower = url.lower()
    f['suspicious_keywords'] = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    tld = '.'+ext.suffix if ext.suffix else ''
    f['suspicious_tld'] = 1 if tld in SUSPICIOUS_TLDS else 0
    f['trusted_tld']    = 1 if tld in TRUSTED_TLDS   else 0
    f['url_entropy']    = entropy(ext.domain)
    f['has_encoding']   = 1 if '%' in url else 0
    f['many_subdomains']= 1 if f['subdomain_count'] > 2 else 0
    f['brand_impersonation'] = 0
    for brand in ['paypal','apple','google','amazon','microsoft','netflix','facebook','instagram']:
        if brand in domain.lower() and ext.domain.lower() != brand:
            f['brand_impersonation'] = 1; break
    return f

def calculate_risk_score(features):
    score, flags = 0, []
    if features['is_ip']:               score+=30; flags.append("IP address used instead of domain name")
    if not features['has_https']:       score+=15; flags.append("No HTTPS encryption")
    if features['suspicious_tld']:      score+=25; flags.append("Suspicious top-level domain")
    if features['url_length'] > 100:    score+=20; flags.append(f"Unusually long URL ({features['url_length']} chars)")
    elif features['url_length'] > 75:   score+=10; flags.append(f"Long URL ({features['url_length']} chars)")
    if features['dot_count'] > 5:       score+=15; flags.append(f"Excessive dots ({features['dot_count']})")
    if features['hyphen_count'] > 3:    score+=15; flags.append(f"Multiple hyphens ({features['hyphen_count']})")
    if features['suspicious_keywords'] >= 3: score+=25; flags.append(f"Multiple suspicious keywords ({features['suspicious_keywords']})")
    elif features['suspicious_keywords'] >= 1: score+=10; flags.append(f"Suspicious keywords ({features['suspicious_keywords']})")
    if features['brand_impersonation']: score+=35; flags.append("Possible brand name impersonation")
    if features['many_subdomains']:     score+=15; flags.append(f"Excessive subdomains ({features['subdomain_count']})")
    if features['has_encoding']:        score+=10; flags.append("URL contains encoded characters")
    if features['url_entropy'] > 3.8:   score+=15; flags.append("Domain appears randomly generated")
    if features['digit_count'] > 3:     score+=10; flags.append(f"Many digits in domain ({features['digit_count']})")
    if features['has_https'] and features['trusted_tld'] and not features['suspicious_keywords']:
        score = max(0, score-10)
    score = min(100, score)
    if score >= 70:   verdict, risk, color = "PHISHING",    "High Risk",   "danger"
    elif score >= 40: verdict, risk, color = "SUSPICIOUS",  "Medium Risk", "warning"
    else:             verdict, risk, color = "LIKELY SAFE", "Low Risk",    "success"
    return {'score':score,'verdict':verdict,'risk_level':risk,'color':color,'flags':flags}

def vt_scan(url):
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
        r = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}',
                         headers=VT_HEADERS, timeout=10)
        if r.status_code == 200:
            stats = r.json().get('data',{}).get('attributes',{}).get('last_analysis_stats',{})
            if stats:
                return {'malicious':stats.get('malicious',0),'suspicious':stats.get('suspicious',0),
                        'harmless':stats.get('harmless',0),'undetected':stats.get('undetected',0),
                        'total':sum(stats.values()),'status':'completed'}
        resp = requests.post('https://www.virustotal.com/api/v3/urls',
                             headers={**VT_HEADERS,'Content-Type':'application/x-www-form-urlencoded'},
                             data={'url':url}, timeout=10)
        if resp.status_code not in (200,201):
            return {'error':f'Submit failed ({resp.status_code})','status':'error'}
        aid = resp.json()['data']['id']
        for _ in range(5):
            time.sleep(4)
            r2   = requests.get(f'https://www.virustotal.com/api/v3/analyses/{aid}',
                                headers=VT_HEADERS, timeout=10)
            attr = r2.json().get('data',{}).get('attributes',{})
            if attr.get('status') == 'completed':
                s = attr.get('stats',{})
                return {'malicious':s.get('malicious',0),'suspicious':s.get('suspicious',0),
                        'harmless':s.get('harmless',0),'undetected':s.get('undetected',0),
                        'total':sum(s.values()),'status':'completed'}
        return {'error':'Scan timed out','status':'timeout'}
    except Exception as e:
        return {'error':str(e),'status':'error'}

THREAT_LABELS = {
    'MALWARE':'Malware','SOCIAL_ENGINEERING':'Phishing / Social Engineering',
    'UNWANTED_SOFTWARE':'Unwanted Software','POTENTIALLY_HARMFUL_APPLICATION':'Potentially Harmful App',
}

def google_sb_scan(url):
    try:
        payload = {
            'client':{'clientId':'phishradar','clientVersion':'1.0'},
            'threatInfo':{'threatTypes':['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],
                          'platformTypes':['ANY_PLATFORM'],'threatEntryTypes':['URL'],
                          'threatEntries':[{'url':url}]}
        }
        resp = requests.post(f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SB_KEY}',
                             json=payload, timeout=10)
        if resp.status_code == 403:
            return {'error':'API key restricted','safe':None}
        if resp.status_code != 200:
            return {'error':f'API error {resp.status_code}','safe':None}
        matches = resp.json().get('matches',[])
        if not matches: return {'safe':True,'threats':[]}
        threats = list({THREAT_LABELS.get(m.get('threatType'),m.get('threatType')) for m in matches})
        return {'safe':False,'threats':threats}
    except Exception as e:
        return {'error':str(e),'safe':None}

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze/quick', methods=['POST'])
def analyze_quick():
    data    = request.get_json()
    url     = data.get('url','').strip()
    if not url:              return jsonify({'error':'No URL provided'}), 400
    if len(url) > 2000:      return jsonify({'error':'URL too long'}), 400
    full_url = url if url.startswith('http') else 'http://'+url

    features = extract_features(full_url)
    result   = calculate_risk_score(features)
    result['url']      = url
    result['features'] = features

    # WHOIS domain age
    ext = tldextract.extract(full_url)
    domain = ext.registered_domain
    age = whois_age(domain) if domain else None
    result['domain_age_days'] = age
    if age is not None and age < 30:
        result['score'] = min(100, result['score'] + 20)
        result['flags'].append(f"Domain registered only {age} days ago (very new)")
        if result['score'] >= 70:
            result['verdict']='PHISHING'; result['risk_level']='High Risk'; result['color']='danger'
    elif age is not None and age < 90:
        result['score'] = min(100, result['score'] + 10)
        result['flags'].append(f"Domain is relatively new ({age} days old)")

    # Google Safe Browsing
    gsb = google_sb_scan(full_url)
    result['google_sb'] = gsb
    if gsb.get('safe') is False:
        result['score'] = min(100, result['score'] + 40)
        for t in gsb.get('threats',[]): result['flags'].append(f"Google Safe Browsing: {t} detected")
        result['verdict']='PHISHING'; result['risk_level']='High Risk'; result['color']='danger'

    # Save partial result to DB
    scan_id = str(uuid.uuid4())[:8]
    result['scan_id'] = scan_id
    result['share_url'] = f'https://phishing.saoud.site/result/{scan_id}'
    save_result(scan_id, result)
    return jsonify(result)

@app.route('/analyze/vt', methods=['POST'])
def analyze_vt():
    data    = request.get_json()
    url     = data.get('url','').strip()
    scan_id = data.get('scan_id','')
    if not url: return jsonify({'error':'No URL provided'}), 400
    full_url = url if url.startswith('http') else 'http://'+url

    vt = vt_scan(full_url)

    # Load and update stored result
    stored = load_result(scan_id) if scan_id else {}
    if stored:
        stored['virustotal'] = vt
        if vt.get('malicious',0) > 0:
            boost = min(30, vt['malicious']*5)
            stored['score'] = min(100, stored['score'] + boost)
            stored['flags'].append(f"VirusTotal: {vt['malicious']}/{vt['total']} engines flagged malicious")
            if stored['score'] >= 70:
                stored['verdict']='PHISHING'; stored['risk_level']='High Risk'; stored['color']='danger'
        save_result(scan_id, stored)
        return jsonify(stored)

    return jsonify({'virustotal': vt})

@app.route('/result/<scan_id>')
def shared_result(scan_id):
    result = load_result(scan_id)
    if not result: abort(404)
    return render_template('index.html', shared_result=json.dumps(result))


# ── VT Lookup Routes ──────────────────────────────────────────────────────────
@app.route('/lookup/ip', methods=['POST'])
def lookup_ip():
    ip = (request.get_json() or {}).get('ip','').strip()
    if not ip: return jsonify({'error':'No IP provided'}), 400
    try:
        r = requests.get(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                         headers=VT_HEADERS, timeout=10)
        if r.status_code == 404: return jsonify({'error':'IP not found in VirusTotal'}), 404
        if r.status_code != 200: return jsonify({'error':f'VT error {r.status_code}'}), 400
        attr  = r.json().get('data',{}).get('attributes',{})
        stats = attr.get('last_analysis_stats',{})
        total = sum(stats.values())
        mal   = stats.get('malicious',0)
        color = 'danger' if mal > 0 else ('warning' if stats.get('suspicious',0) > 0 else 'success')
        return jsonify({
            'ip':         ip,
            'country':    attr.get('country','Unknown'),
            'asn':        attr.get('asn'),
            'as_owner':   attr.get('as_owner','Unknown'),
            'network':    attr.get('network',''),
            'malicious':  mal,
            'suspicious': stats.get('suspicious',0),
            'harmless':   stats.get('harmless',0),
            'undetected': stats.get('undetected',0),
            'total':      total,
            'reputation': attr.get('reputation',0),
            'tags':       attr.get('tags',[]),
            'color':      color,
            'verdict':    'MALICIOUS' if mal > 0 else ('SUSPICIOUS' if stats.get('suspicious',0) > 0 else 'CLEAN'),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/lookup/domain', methods=['POST'])
def lookup_domain():
    domain = (request.get_json() or {}).get('domain','').strip().lower()
    if not domain: return jsonify({'error':'No domain provided'}), 400
    # Strip protocol if pasted with it
    domain = re.sub(r'^https?://', '', domain).split('/')[0]
    try:
        r = requests.get(f'https://www.virustotal.com/api/v3/domains/{domain}',
                         headers=VT_HEADERS, timeout=10)
        if r.status_code == 404: return jsonify({'error':'Domain not found in VirusTotal'}), 404
        if r.status_code != 200: return jsonify({'error':f'VT error {r.status_code}'}), 400
        attr  = r.json().get('data',{}).get('attributes',{})
        stats = attr.get('last_analysis_stats',{})
        total = sum(stats.values())
        mal   = stats.get('malicious',0)
        color = 'danger' if mal > 0 else ('warning' if stats.get('suspicious',0) > 0 else 'success')

        # Creation date
        cd = attr.get('creation_date')
        age_str = None
        if cd:
            try:
                age = (datetime.now() - datetime.fromtimestamp(cd)).days
                age_str = f'{age} days'
            except: pass

        cats = attr.get('categories',{})
        categories = list(set(cats.values())) if cats else []

        return jsonify({
            'domain':     domain,
            'malicious':  mal,
            'suspicious': stats.get('suspicious',0),
            'harmless':   stats.get('harmless',0),
            'undetected': stats.get('undetected',0),
            'total':      total,
            'reputation': attr.get('reputation',0),
            'tags':       attr.get('tags',[]),
            'registrar':  attr.get('registrar','Unknown'),
            'age':        age_str,
            'categories': categories,
            'color':      color,
            'verdict':    'MALICIOUS' if mal > 0 else ('SUSPICIOUS' if stats.get('suspicious',0) > 0 else 'CLEAN'),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/lookup/hash', methods=['POST'])
def lookup_hash():
    h = (request.get_json() or {}).get('hash','').strip().lower()
    if not h: return jsonify({'error':'No hash provided'}), 400
    if len(h) not in (32, 40, 64):
        return jsonify({'error':'Invalid hash — provide MD5 (32), SHA1 (40), or SHA256 (64) characters'}), 400
    try:
        r = requests.get(f'https://www.virustotal.com/api/v3/files/{h}',
                         headers=VT_HEADERS, timeout=10)
        if r.status_code == 404: return jsonify({'error':'Hash not found — file may not have been scanned before'}), 404
        if r.status_code != 200: return jsonify({'error':f'VT error {r.status_code}'}), 400
        attr  = r.json().get('data',{}).get('attributes',{})
        stats = attr.get('last_analysis_stats',{})
        total = sum(stats.values())
        mal   = stats.get('malicious',0)
        color = 'danger' if mal > 0 else ('warning' if stats.get('suspicious',0) > 0 else 'success')

        names = attr.get('names',[])
        sig   = attr.get('meaningful_name') or (names[0] if names else 'Unknown')
        size  = attr.get('size',0)
        size_str = f'{size/1024:.1f} KB' if size < 1024*1024 else f'{size/1024/1024:.1f} MB'

        # Threat names from engines
        results   = attr.get('last_analysis_results',{})
        threats   = list({v.get('result') for v in results.values() if v.get('category') == 'malicious' and v.get('result')})[:5]

        return jsonify({
            'hash':       h,
            'hash_type':  'MD5' if len(h)==32 else ('SHA1' if len(h)==40 else 'SHA256'),
            'name':       sig,
            'size':       size_str,
            'type':       attr.get('type_description','Unknown'),
            'malicious':  mal,
            'suspicious': stats.get('suspicious',0),
            'harmless':   stats.get('harmless',0),
            'undetected': stats.get('undetected',0),
            'total':      total,
            'threats':    threats,
            'color':      color,
            'verdict':    'MALICIOUS' if mal > 0 else ('SUSPICIOUS' if stats.get('suspicious',0) > 0 else 'CLEAN'),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    return jsonify({'status':'ok'})

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
