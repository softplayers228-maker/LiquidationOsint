#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LiquidationOsint — Production Flask App
Auth · Admin · SEO · Logging · Railway-ready
"""

from flask import (Flask, request, render_template, redirect,
                   url_for, session, flash, jsonify, g)
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, hashlib, os, re, time, json
import requests, urllib.parse, socket
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "liquidation-osint-secret-change-me-2024")

ADMIN_EMAIL   = os.environ.get("ADMIN_EMAIL", "admin@liquidationosint.com")
ADMIN_PASS    = os.environ.get("ADMIN_PASS",  "admin1234")   # меняй в Railway env vars
SITE_NAME     = "LiquidationOsint"
SITE_URL      = os.environ.get("SITE_URL", "https://liquidationosint.up.railway.app")
AUTHOR        = "@poyasnitelno"
TIKTOK        = "https://www.tiktok.com/@poyasnitelno"
DB_PATH       = os.environ.get("DB_PATH", "liquidation.db")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8",
}

# ═══════════════════════════════════════════════════════════════
#  DATABASE
# ═══════════════════════════════════════════════════════════════
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db: db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        email       TEXT UNIQUE NOT NULL,
        username    TEXT NOT NULL,
        password    TEXT,
        avatar      TEXT,
        role        TEXT DEFAULT 'user',
        is_banned   INTEGER DEFAULT 0,
        created_at  TEXT DEFAULT (datetime('now')),
        last_login  TEXT,
        login_count INTEGER DEFAULT 0,
        ip          TEXT,
        country     TEXT
    );
    CREATE TABLE IF NOT EXISTS searches (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER,
        query      TEXT NOT NULL,
        qtype      TEXT,
        ip         TEXT,
        user_agent TEXT,
        results    INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS visitors (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ip         TEXT,
        path       TEXT,
        method     TEXT,
        user_agent TEXT,
        referer    TEXT,
        country    TEXT,
        city       TEXT,
        isp        TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS settings (
        key   TEXT PRIMARY KEY,
        value TEXT
    );
    INSERT OR IGNORE INTO settings VALUES ('require_login','0');
    INSERT OR IGNORE INTO settings VALUES ('maintenance','0');
    INSERT OR IGNORE INTO settings VALUES ('max_searches_per_day','100');
    """)
    # Create admin account
    pw = hashlib.sha256(ADMIN_PASS.encode()).hexdigest()
    db.execute("""
        INSERT OR IGNORE INTO users (email, username, password, role)
        VALUES (?, 'Admin', ?, 'admin')
    """, (ADMIN_EMAIL, pw))
    db.commit()
    db.close()

# ═══════════════════════════════════════════════════════════════
#  AUTH HELPERS
# ═══════════════════════════════════════════════════════════════
def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

def current_user():
    uid = session.get("user_id")
    if not uid: return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        db = get_db()
        req_login = db.execute("SELECT value FROM settings WHERE key='require_login'").fetchone()
        if req_login and req_login["value"] == "1" and not session.get("user_id"):
            flash("Войдите чтобы пользоваться сайтом", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = current_user()
        if not user or user["role"] != "admin":
            flash("Нет доступа", "error")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated

def log_visitor_db(ip, path, method, ua, referer=""):
    try:
        geo = {}
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,isp",timeout=3).json()
            geo = {"country": r.get("country",""), "city": r.get("city",""), "isp": r.get("isp","")}
        except: pass
        db = get_db()
        db.execute("""INSERT INTO visitors (ip,path,method,user_agent,referer,country,city,isp)
                      VALUES (?,?,?,?,?,?,?,?)""",
                   (ip, path, method, ua[:200], referer[:200],
                    geo.get("country",""), geo.get("city",""), geo.get("isp","")))
        db.commit()
    except: pass

# ═══════════════════════════════════════════════════════════════
#  OSINT CORE (same as before, compact)
# ═══════════════════════════════════════════════════════════════
def detect_type(q):
    q = q.strip()
    if re.match(r"^\+?\d[\d\s\-()]{7,14}$", q):             return "phone"
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", q):          return "email"
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", q):              return "ip"
    if re.match(r"^[0-9a-fA-F:]{7,}$", q) and ":" in q:      return "ip"
    if re.search(r"\d{1,2}[.\-/]\d{1,2}[.\-/]\d{2,4}", q):  return "birthday"
    if re.match(r"^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$", q) and " " not in q: return "domain"
    words = q.split()
    if 2 <= len(words) <= 4 and all(re.match(r"^[а-яёА-ЯЁa-zA-Z\-]+$", w) for w in words):
        return "fullname"
    return "username"

def google_search(query, limit=10):
    url = "https://www.google.com/search?q=" + urllib.parse.quote(f'"{query}"') + "&hl=ru&num=10"
    try:
        r = requests.get(url, headers=HEADERS, timeout=12)
        soup = BeautifulSoup(r.text, "html.parser")
        results = []
        for g in soup.select("div.g")[:limit]:
            h = g.find("h3"); a = g.find("a")
            snip = g.find("div", attrs={"data-sncf": True}) or g.find("span")
            href = ""
            if a:
                href = a.get("href","")
                if href.startswith("/url?q="): href = urllib.parse.unquote(href[7:].split("&")[0])
            results.append({"title": h.get_text() if h else "", "url": href if href.startswith("http") else "",
                             "snippet": snip.get_text()[:180] if snip else ""})
        return [r for r in results if r["title"]]
    except: return []

def build_dorks(query, qtype):
    base = {
        "phone":    [("Соцсети", f'"{query}" site:vk.com OR site:ok.ru OR site:facebook.com'),
                     ("Объявления", f'"{query}" site:avito.ru OR site:youla.ru'),
                     ("Telegram", f'"{query}" site:t.me OR site:wa.me'),
                     ("Форумы", f'"{query}" форум OR чат OR отзывы'),
                     ("Утечки", f'"{query}" leaked OR слив OR база'),
                     ("Google", f'"{query}"')],
        "email":    [("GitHub", f'"{query}" site:github.com OR site:gitlab.com'),
                     ("Утечки", f'"{query}" password OR leaked OR breach'),
                     ("Файлы", f'"{query}" filetype:pdf OR filetype:doc'),
                     ("Соцсети", f'"{query}" site:vk.com OR site:linkedin.com'),
                     ("Pastebin", f'"{query}" site:pastebin.com'),
                     ("Google", f'"{query}"')],
        "ip":       [("Упоминания", f'"{query}"'),
                     ("Shodan", f'"{query}" site:shodan.io OR site:censys.io'),
                     ("Abuse", f'"{query}" abuse OR spam OR blacklist'),
                     ("Логи", f'"{query}" access.log OR error.log')],
        "domain":   [("Субдомены", f'site:{query}'),
                     ("Технологии", f'"{query}" site:builtwith.com'),
                     ("Pastebin", f'"{query}" site:pastebin.com OR dump'),
                     ("PDF/Docs", f'site:{query} filetype:pdf'),
                     ("Robots", f'site:{query}/robots.txt')],
        "username": [("VK", f'site:vk.com "{query}"'),
                     ("GitHub", f'site:github.com "{query}"'),
                     ("Reddit", f'site:reddit.com/user "{query}"'),
                     ("Twitter", f'site:twitter.com "{query}"'),
                     ("Lolz", f'"{query}" site:lolz.live OR site:exploit.in'),
                     ("Telegram", f'site:t.me "{query}"'),
                     ("Pastebin", f'site:pastebin.com "{query}"')],
        "fullname": [("VK", f'site:vk.com "{query}"'),
                     ("LinkedIn", f'site:linkedin.com "{query}"'),
                     ("Суды", f'"{query}" site:sudact.ru OR site:kad.arbitr.ru'),
                     ("СМИ", f'"{query}" site:rbc.ru OR site:ria.ru'),
                     ("PDF", f'"{query}" filetype:pdf')],
        "birthday": [("VK", f'"{query}" site:vk.com день рождения'),
                     ("Google", f'"{query}"'),
                     ("Yandex", f'"{query}" паспорт OR дата рождения')],
    }
    dorks_raw = base.get(qtype, [("Поиск", f'"{query}"')])
    return [{"name": n, "dork": d,
             "url": "https://www.google.com/search?q=" + urllib.parse.quote(d) + "&hl=ru"}
            for n, d in dorks_raw]

SHERLOCK_SITES = [
    ("GitHub","https://github.com/{u}",200), ("GitLab","https://gitlab.com/{u}",200),
    ("Reddit","https://www.reddit.com/user/{u}",200), ("Twitter/X","https://twitter.com/{u}",200),
    ("Instagram","https://www.instagram.com/{u}/",200), ("TikTok","https://www.tiktok.com/@{u}",200),
    ("Pinterest","https://www.pinterest.com/{u}/",200), ("Twitch","https://www.twitch.tv/{u}",200),
    ("YouTube","https://www.youtube.com/@{u}",200), ("SoundCloud","https://soundcloud.com/{u}",200),
    ("Steam","https://steamcommunity.com/id/{u}",200), ("Telegram","https://t.me/{u}",200),
    ("VKontakte","https://vk.com/{u}",200), ("OK.ru","https://ok.ru/{u}",200),
    ("LinkedIn","https://www.linkedin.com/in/{u}/",200), ("Medium","https://medium.com/@{u}",200),
    ("Dev.to","https://dev.to/{u}",200), ("Pastebin","https://pastebin.com/u/{u}",200),
    ("HackerNews","https://news.ycombinator.com/user?id={u}",200),
    ("Behance","https://www.behance.net/{u}",200), ("Dribbble","https://dribbble.com/{u}",200),
    ("Flickr","https://www.flickr.com/people/{u}/",200), ("Keybase","https://keybase.io/{u}",200),
    ("Replit","https://replit.com/@{u}",200), ("Codepen","https://codepen.io/{u}",200),
    ("PyPI","https://pypi.org/user/{u}/",200), ("Letterboxd","https://letterboxd.com/{u}/",200),
    ("Last.fm","https://www.last.fm/user/{u}",200), ("Chess.com","https://www.chess.com/member/{u}",200),
    ("Lichess","https://lichess.org/@/{u}",200), ("Kick","https://kick.com/{u}",200),
    ("Lolzteam","https://lolz.live/{u}/",200), ("Habr","https://habr.com/ru/users/{u}/",200),
    ("Pikabu","https://pikabu.ru/@{u}",200), ("VC.ru","https://vc.ru/u/{u}",200),
    ("About.me","https://about.me/{u}",200), ("Npmjs","https://www.npmjs.com/~{u}",200),
    ("Duolingo","https://www.duolingo.com/profile/{u}",200),
    ("ProductHunt","https://www.producthunt.com/@{u}",200),
    ("Spotify","https://open.spotify.com/user/{u}",200), ("Tumblr","https://{u}.tumblr.com",200),
    ("WordPress","https://{u}.wordpress.com",200), ("Gitea","https://gitea.com/{u}",200),
    ("Goodreads","https://www.goodreads.com/{u}",200), ("Imgur","https://imgur.com/user/{u}",200),
    ("HackerOne","https://hackerone.com/{u}",200), ("Bitbucket","https://bitbucket.org/{u}/",200),
    ("Mastodon","https://mastodon.social/@{u}",200), ("Bluesky","https://bsky.app/profile/{u}.bsky.social",200),
    ("Substack","https://{u}.substack.com",200), ("Vimeo","https://vimeo.com/{u}",200),
    ("Wattpad","https://www.wattpad.com/user/{u}",200), ("Disqus","https://disqus.com/by/{u}/",200),
    ("Snapchat","https://www.snapchat.com/add/{u}",200), ("Gravatar","https://gravatar.com/{u}",200),
    ("Rumble","https://rumble.com/c/{u}",200), ("Dailymotion","https://www.dailymotion.com/{u}",200),
    ("Fiverr","https://www.fiverr.com/{u}",200), ("Freelancer","https://www.freelancer.com/u/{u}",200),
    ("ArtStation","https://www.artstation.com/{u}",200), ("Deviantart","https://www.deviantart.com/{u}",200),
]

def _check_one(u, name, tpl, code):
    url = tpl.replace("{u}", urllib.parse.quote(u))
    try:
        r = requests.get(url, headers=HEADERS, timeout=7, allow_redirects=True)
        found = (r.status_code == code)
        if found and any(x in r.text.lower() for x in ["not found","user not found","doesn't exist","page not found","пользователь не найден"]):
            found = False
        return {"name": name, "url": url, "found": found}
    except:
        return {"name": name, "url": url, "found": None}

def sherlock_check(username):
    results = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_check_one, username, n, t, c): n for n, t, c in SHERLOCK_SITES}
        for f in as_completed(futures): results.append(f.result())
    results.sort(key=lambda x: (0 if x["found"] else (2 if x["found"] is None else 1), x["name"]))
    return results

def shodan_lookup(ip):
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=8).json()
        return {"ports": r.get("ports",[]), "cves": r.get("cves",[]),
                "tags": r.get("tags",[]), "hostnames": r.get("hostnames",[])}
    except: return {}

def lookup_ip(ip):
    out = {}
    try:
        d = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,mobile,proxy,hosting", timeout=8).json()
        if d.get("status") == "success":
            out["Страна"] = d.get("country",""); out["Город"] = d.get("city","")
            out["Регион"] = d.get("regionName",""); out["Индекс"] = d.get("zip","")
            out["Координаты"] = f"{d.get('lat','')} , {d.get('lon','')}"
            out["Часовой пояс"] = d.get("timezone",""); out["ISP"] = d.get("isp","")
            out["Организация"] = d.get("org",""); out["AS"] = d.get("as","")
            out["Reverse DNS"] = d.get("reverse","") or "—"
            out["Мобильный"] = "Да" if d.get("mobile") else "Нет"
            out["Прокси/VPN"] = "⚠ ДА" if d.get("proxy") else "Нет"
            out["Хостинг/ДЦ"] = "⚠ ДА" if d.get("hosting") else "Нет"
            out["_map"] = f"https://maps.google.com/?q={d['lat']},{d['lon']}"
    except: pass
    try:
        ptr = socket.gethostbyaddr(ip)[0]
        if ptr: out["PTR"] = ptr
    except: pass
    out["_links"] = [
        ("Shodan", f"https://www.shodan.io/host/{ip}"),
        ("Censys", f"https://search.censys.io/hosts/{ip}"),
        ("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{ip}"),
        ("AbuseIPDB", f"https://www.abuseipdb.com/check/{ip}"),
        ("IPVoid", f"https://www.ipvoid.com/ip-blacklist-check/?ip={ip}"),
        ("GreyNoise", f"https://www.greynoise.io/viz/ip/{ip}"),
        ("BGP HE", f"https://bgp.he.net/ip/{ip}"),
        ("Google Maps", out.get("_map","")),
    ]
    return out

def lookup_phone(phone):
    digits = re.sub(r"\D","",phone)
    if len(digits)==10: digits = "7"+digits
    out = {"Номер": f"+{digits}"}
    try:
        d = requests.get(f"https://api.numlookup.com/?q=+{digits}&type=json", headers=HEADERS, timeout=8).json()
        out["Страна"] = d.get("country_name",""); out["Оператор"] = d.get("carrier","")
        out["Тип линии"] = d.get("line_type",""); out["Валидный"] = "Да" if d.get("valid") else "Нет"
    except: pass
    try:
        md5 = hashlib.md5(f"+{digits}".encode()).hexdigest()
        g_data = requests.get(f"https://www.gravatar.com/{md5}.json", timeout=5).json()
        if "entry" in g_data:
            e = g_data["entry"][0]
            out["Gravatar имя"] = e.get("displayName","")
            out["Gravatar username"] = e.get("preferredUsername","")
    except: pass
    out["_links"] = [
        ("GetContact", f"https://getcontact.com/en/search?q=%2B{digits}"),
        ("TrueCaller", f"https://www.truecaller.com/search/ru/{digits}"),
        ("NumLookup", f"https://www.numlookup.com/?q=%2B{digits}"),
        ("SpamCalls", f"https://spamcalls.net/ru/phone/{digits}"),
        ("Avito", f"https://www.avito.ru/all?q=%2B{digits}"),
        ("Google", f"https://www.google.com/search?q=%22%2B{digits}%22"),
        ("VK", f"https://vk.com/search?c[q]=%2B{digits}&c[section]=people"),
        ("Telegram", f"https://t.me/+{digits}"),
        ("WhatsApp", f"https://wa.me/{digits}"),
    ]
    return out

def lookup_email(email):
    email = email.strip().lower()
    domain = email.split("@")[-1]; local = email.split("@")[0]
    out = {"Домен": domain}
    try:
        md5 = hashlib.md5(email.encode()).hexdigest()
        g_data = requests.get(f"https://www.gravatar.com/{md5}.json", timeout=5).json()
        if "entry" in g_data:
            e = g_data["entry"][0]
            out["Gravatar имя"] = e.get("displayName","")
            out["Gravatar username"] = e.get("preferredUsername","")
            out["Gravatar фото"] = (e.get("photos") or [{}])[0].get("value","")
        out["Gravatar MD5"] = md5
    except: pass
    parts = re.split(r"[._\-]", local); stripped = re.sub(r"\d+$","",local)
    unames = list(dict.fromkeys([local, stripped] + parts))
    out["Возможные username"] = ", ".join(u for u in unames if len(u)>=3)
    disposable = ["mailinator.com","guerrillamail.com","10minutemail.com","tempmail.com"]
    out["Одноразовый"] = "⚠ Возможно" if domain in disposable else "Нет"
    out["_links"] = [
        ("HaveIBeenPwned", f"https://haveibeenpwned.com/account/{urllib.parse.quote(email)}"),
        ("Epieos", f"https://epieos.com/?q={urllib.parse.quote(email)}&t=email"),
        ("Hunter.io", f"https://hunter.io/verify/{urllib.parse.quote(email)}"),
        ("IntelX", f"https://intelx.io/?s={urllib.parse.quote(email)}"),
        ("LeakCheck", f"https://leakcheck.io/check?query={urllib.parse.quote(email)}"),
        ("GitHub", f"https://github.com/search?q={urllib.parse.quote(email)}&type=users"),
        ("Gravatar", f"https://www.gravatar.com/{hashlib.md5(email.encode()).hexdigest()}"),
        ("EmailRep", f"https://emailrep.io/{urllib.parse.quote(email)}"),
    ]
    return out

def lookup_username(username):
    out = {}
    try:
        gh = requests.get(f"https://api.github.com/users/{urllib.parse.quote(username)}", timeout=8).json()
        if "login" in gh:
            out["GitHub имя"] = gh.get("name",""); out["GitHub bio"] = (gh.get("bio","") or "")[:80]
            out["GitHub локация"] = gh.get("location","") or "—"
            out["GitHub репо"] = str(gh.get("public_repos",0))
            out["GitHub followers"] = str(gh.get("followers",0))
            out["GitHub создан"] = str(gh.get("created_at",""))[:10]
            out["GitHub аватар"] = gh.get("avatar_url","")
    except: pass
    out["_links"] = [
        ("GitHub", f"https://github.com/{username}"), ("VK", f"https://vk.com/{username}"),
        ("Telegram", f"https://t.me/{username}"), ("Instagram", f"https://instagram.com/{username}"),
        ("TikTok", f"https://tiktok.com/@{username}"), ("Twitter/X", f"https://twitter.com/{username}"),
        ("Reddit", f"https://reddit.com/user/{username}"), ("YouTube", f"https://youtube.com/@{username}"),
        ("Steam", f"https://steamcommunity.com/id/{username}"), ("Twitch", f"https://twitch.tv/{username}"),
    ]
    return out

def lookup_fullname(name):
    out = {"ФИО": name}
    tr = {"а":"a","б":"b","в":"v","г":"g","д":"d","е":"e","ё":"yo","ж":"zh","з":"z","и":"i","й":"y","к":"k","л":"l","м":"m","н":"n","о":"o","п":"p","р":"r","с":"s","т":"t","у":"u","ф":"f","х":"kh","ц":"ts","ч":"ch","ш":"sh","щ":"shch","ъ":"","ы":"y","ь":"","э":"e","ю":"yu","я":"ya"}
    translit = "".join(tr.get(c.lower(),c) for c in name)
    out["Транслит"] = translit
    out["_links"] = [
        ("VK", f"https://vk.com/search?c[q]={urllib.parse.quote(name)}&c[section]=people"),
        ("OK.ru", f"https://ok.ru/search?query={urllib.parse.quote(name)}"),
        ("LinkedIn", f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(name)}"),
        ("Google", f"https://www.google.com/search?q=%22{urllib.parse.quote(name)}%22"),
        ("Судебные", f"https://sudact.ru/regular/court/?regular-defendant={urllib.parse.quote(name)}"),
    ]
    return out

def lookup_birthday(dob):
    out = {"Дата рождения": dob}
    parts = re.split(r"[.\-/]", dob)
    if len(parts)==3:
        day, month, year = parts[0].zfill(2), parts[1].zfill(2), parts[2]
        if len(year)==2: year = ("20" if int(year)<30 else "19")+year
        out["Формат"] = f"{day}.{month}.{year}"
        out["Примерный возраст"] = f"{datetime.now().year - int(year)} лет"
        out["_links"] = [
            ("VK по ДР", f"https://vk.com/search?c[section]=people&c[birth_day]={day}&c[birth_month]={month}&c[birth_year]={year}"),
            ("Google", f"https://www.google.com/search?q=%22{urllib.parse.quote(day+'.'+month+'.'+year)}%22"),
        ]
    return out

def lookup_domain(domain):
    out = {"Домен": domain}
    try:
        import whois as pw
        w = pw.whois(domain)
        if w:
            out["Регистратор"] = str(w.registrar or "")[:60]
            out["Создан"] = str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date)[:10]
            out["Истекает"] = str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date)[:10]
            ns = w.name_servers
            if ns: out["Nameservers"] = ", ".join(list(ns)[:4]) if isinstance(ns,(list,set)) else str(ns)
    except:
        try:
            rdap = requests.get(f"https://rdap.org/domain/{domain}", timeout=7).json()
            for ev in rdap.get("events",[]):
                if ev.get("eventAction") == "registration": out["Создан"] = ev.get("eventDate","")[:10]
        except: pass
    try:
        crt = requests.get(f"https://crt.sh/?q={domain}&output=json", timeout=8).json()
        subs = list(set(c.get("name_value","") for c in crt[:20] if c.get("name_value")))
        if subs: out["Субдомены"] = ", ".join(subs[:6])
    except: pass
    try:
        ip = socket.gethostbyname(domain)
        out["IP адрес"] = ip
    except: pass
    out["_links"] = [
        ("WHOIS", f"https://whois.domaintools.com/{domain}"),
        ("Shodan", f"https://www.shodan.io/search?query=hostname%3A{domain}"),
        ("VirusTotal", f"https://www.virustotal.com/gui/domain/{domain}"),
        ("crt.sh", f"https://crt.sh/?q={domain}"),
        ("Wayback", f"https://web.archive.org/web/*/{domain}"),
        ("URLScan", f"https://urlscan.io/search/#domain:{domain}"),
        ("SecurityTrails", f"https://securitytrails.com/domain/{domain}/dns"),
        ("BuildWith", f"https://builtwith.com/{domain}"),
        ("Google", f"https://www.google.com/search?q=site:{domain}"),
    ]
    return out

SOCIAL_SITES = [
    ("VKontakte","vk.com"),("Telegram","t.me"),("GitHub","github.com"),
    ("Instagram","instagram.com"),("YouTube","youtube.com"),("Twitter/X","twitter.com"),
    ("TikTok","tiktok.com"),("Pastebin","pastebin.com"),("Reddit","reddit.com"),
    ("LinkedIn","linkedin.com"),("Facebook","facebook.com"),("OK.ru","ok.ru"),
    ("Habr","habr.com"),("Pikabu","pikabu.ru"),("VC.ru","vc.ru"),
]

def site_check(query):
    results = []
    for name, site in SOCIAL_SITES:
        q = f'site:{site} "{query}"'
        url = "https://www.google.com/search?q=" + urllib.parse.quote(q)
        try:
            r = requests.get(url, headers=HEADERS, timeout=8)
            soup = BeautifulSoup(r.text, "html.parser")
            hits = soup.find_all("h3")
            results.append({"name":name,"site":site,"found":len(hits)>0,"count":len(hits),"link":f"https://{site}/"})
        except:
            results.append({"name":name,"site":site,"found":None,"count":0,"link":""})
        time.sleep(0.07)
    return results

# ═══════════════════════════════════════════════════════════════
#  ROUTES — AUTH
# ═══════════════════════════════════════════════════════════════
@app.route("/register", methods=["GET","POST"])
def register():
    if session.get("user_id"): return redirect(url_for("index"))
    if request.method == "POST":
        email    = request.form.get("email","").strip().lower()
        username = request.form.get("username","").strip()
        pw       = request.form.get("password","")
        pw2      = request.form.get("password2","")
        if not email or not username or not pw:
            flash("Заполни все поля", "error")
        elif pw != pw2:
            flash("Пароли не совпадают", "error")
        elif len(pw) < 6:
            flash("Пароль минимум 6 символов", "error")
        else:
            db = get_db()
            existing = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
            if existing:
                flash("Email уже зарегистрирован", "error")
            else:
                ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
                db.execute(
                    "INSERT INTO users (email,username,password,ip,last_login) VALUES (?,?,?,?,?)",
                    (email, username, hash_pw(pw), ip, datetime.now().isoformat())
                )
                db.commit()
                user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
                session["user_id"] = user["id"]
                flash(f"Добро пожаловать, {username}! 🎉", "success")
                return redirect(url_for("index"))
    return render_template("auth.html", page="register", sitename=SITE_NAME)

@app.route("/login", methods=["GET","POST"])
def login():
    if session.get("user_id"): return redirect(url_for("index"))
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        pw    = request.form.get("password","")
        db    = get_db()
        user  = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not user or user["password"] != hash_pw(pw):
            flash("Неверный email или пароль", "error")
        elif user["is_banned"]:
            flash("Аккаунт заблокирован", "error")
        else:
            ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
            db.execute("UPDATE users SET last_login=?, login_count=login_count+1, ip=? WHERE id=?",
                       (datetime.now().isoformat(), ip, user["id"]))
            db.commit()
            session["user_id"] = user["id"]
            flash(f"Добро пожаловать, {user['username']}!", "success")
            return redirect(url_for("index"))
    return render_template("auth.html", page="login", sitename=SITE_NAME)

@app.route("/logout")
def logout():
    session.clear()
    flash("Вы вышли из аккаунта", "info")
    return redirect(url_for("index"))

# ═══════════════════════════════════════════════════════════════
#  ROUTES — MAIN
# ═══════════════════════════════════════════════════════════════
@app.before_request
def before_request():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    ua = request.headers.get("User-Agent","")
    referer = request.headers.get("Referer","")
    if not request.path.startswith("/static") and not request.path.startswith("/admin/api"):
        log_visitor_db(ip, request.path, request.method, ua, referer)

@app.route("/", methods=["GET","POST"])
@login_required
def index():
    user = current_user()
    query=None; qtype=None; lookup_data={}
    google_results=[]; site_results=[]; dorks=[]
    sherlock_results=[]; shodan_data={}

    if request.method == "POST":
        query = request.form.get("query","").strip()
        if query:
            qtype = detect_type(query)
            ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

            if qtype == "phone":      lookup_data = lookup_phone(query)
            elif qtype == "email":    lookup_data = lookup_email(query)
            elif qtype == "ip":
                lookup_data = lookup_ip(query); shodan_data = shodan_lookup(query)
            elif qtype == "domain":   lookup_data = lookup_domain(query)
            elif qtype == "username":
                lookup_data = lookup_username(query); sherlock_results = sherlock_check(query)
            elif qtype == "fullname": lookup_data = lookup_fullname(query)
            elif qtype == "birthday": lookup_data = lookup_birthday(query)

            google_results = google_search(query)
            dorks          = build_dorks(query, qtype)
            site_results   = site_check(query)

            # Log search
            db = get_db()
            db.execute("INSERT INTO searches (user_id,query,qtype,ip,user_agent,results) VALUES (?,?,?,?,?,?)",
                       (user["id"] if user else None, query, qtype, ip,
                        request.headers.get("User-Agent","")[:200],
                        len(google_results) + len([s for s in sherlock_results if s.get("found")])))
            db.commit()

    return render_template("index.html",
        query=query, qtype=qtype, lookup_data=lookup_data,
        google_results=google_results, site_results=site_results,
        dorks=dorks, sherlock_results=sherlock_results,
        shodan_data=shodan_data, user=user,
        sitename=SITE_NAME, author=AUTHOR, tiktok=TIKTOK)

# ═══════════════════════════════════════════════════════════════
#  ROUTES — PROFILE
# ═══════════════════════════════════════════════════════════════
@app.route("/profile")
def profile():
    user = current_user()
    if not user: return redirect(url_for("login"))
    db = get_db()
    searches = db.execute(
        "SELECT * FROM searches WHERE user_id=? ORDER BY created_at DESC LIMIT 30",
        (user["id"],)
    ).fetchall()
    return render_template("profile.html", user=user, searches=searches, sitename=SITE_NAME)

# ═══════════════════════════════════════════════════════════════
#  ROUTES — ADMIN
# ═══════════════════════════════════════════════════════════════
@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    users_list   = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    searches_list= db.execute("SELECT s.*,u.username,u.email FROM searches s LEFT JOIN users u ON s.user_id=u.id ORDER BY s.created_at DESC LIMIT 100").fetchall()
    visitors_list= db.execute("SELECT * FROM visitors ORDER BY created_at DESC LIMIT 200").fetchall()
    stats = {
        "total_users":   db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "total_searches":db.execute("SELECT COUNT(*) FROM searches").fetchone()[0],
        "total_visitors":db.execute("SELECT COUNT(*) FROM visitors").fetchone()[0],
        "today_searches":db.execute("SELECT COUNT(*) FROM searches WHERE date(created_at)=date('now')").fetchone()[0],
        "today_visitors":db.execute("SELECT COUNT(*) FROM visitors WHERE date(created_at)=date('now')").fetchone()[0],
        "top_queries":   db.execute("SELECT query,COUNT(*) as c FROM searches GROUP BY query ORDER BY c DESC LIMIT 10").fetchall(),
        "top_ips":       db.execute("SELECT ip,COUNT(*) as c FROM visitors GROUP BY ip ORDER BY c DESC LIMIT 10").fetchall(),
    }
    settings = {row["key"]: row["value"] for row in db.execute("SELECT * FROM settings").fetchall()}
    return render_template("admin.html",
        users=users_list, searches=searches_list, visitors=visitors_list,
        stats=stats, settings=settings, sitename=SITE_NAME, user=current_user())

@app.route("/admin/user/<int:uid>/ban", methods=["POST"])
@admin_required
def admin_ban(uid):
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if u and u["role"] != "admin":
        new_val = 0 if u["is_banned"] else 1
        db.execute("UPDATE users SET is_banned=? WHERE id=?", (new_val, uid))
        db.commit()
        flash(f"Пользователь {'заблокирован' if new_val else 'разблокирован'}", "success")
    return redirect(url_for("admin"))

@app.route("/admin/user/<int:uid>/delete", methods=["POST"])
@admin_required
def admin_delete_user(uid):
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if u and u["role"] != "admin":
        db.execute("DELETE FROM users WHERE id=?", (uid,))
        db.execute("DELETE FROM searches WHERE user_id=?", (uid,))
        db.commit()
        flash("Пользователь удалён", "success")
    return redirect(url_for("admin"))

@app.route("/admin/settings", methods=["POST"])
@admin_required
def admin_settings():
    db = get_db()
    for key in ["require_login", "maintenance", "max_searches_per_day"]:
        val = request.form.get(key, "0")
        db.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", (key, val))
    db.commit()
    flash("Настройки сохранены", "success")
    return redirect(url_for("admin"))

@app.route("/admin/api/stats")
@admin_required
def admin_api_stats():
    db = get_db()
    # searches per day last 14 days
    daily = db.execute("""
        SELECT date(created_at) as d, COUNT(*) as c
        FROM searches WHERE created_at >= date('now','-14 days')
        GROUP BY d ORDER BY d
    """).fetchall()
    # users per day last 14 days
    users_daily = db.execute("""
        SELECT date(created_at) as d, COUNT(*) as c
        FROM users WHERE created_at >= date('now','-14 days')
        GROUP BY d ORDER BY d
    """).fetchall()
    return jsonify({
        "searches_daily": [{"date": r["d"], "count": r["c"]} for r in daily],
        "users_daily":    [{"date": r["d"], "count": r["c"]} for r in users_daily],
    })

# ═══════════════════════════════════════════════════════════════
#  SEO
# ═══════════════════════════════════════════════════════════════
@app.route("/sitemap.xml")
def sitemap():
    pages = ["", "/login", "/register"]
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for p in pages:
        xml += f"  <url><loc>{SITE_URL}{p}</loc><changefreq>weekly</changefreq><priority>0.8</priority></url>\n"
    xml += "</urlset>"
    return xml, 200, {"Content-Type": "application/xml"}

@app.route("/robots.txt")
def robots():
    txt = f"User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /admin/*\nSitemap: {SITE_URL}/sitemap.xml"
    return txt, 200, {"Content-Type": "text/plain"}

# ═══════════════════════════════════════════════════════════════
#  RUN
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  ◈ {SITE_NAME}")
    print(f"  ◈ http://localhost:{port}")
    print(f"  ◈ Admin: {ADMIN_EMAIL} / {ADMIN_PASS}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
