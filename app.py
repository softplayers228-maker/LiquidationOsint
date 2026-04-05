#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LiquidationOsint v2.0 — Ultimate OSINT Framework
AI Assistant · Persistent Login · GHunt-style · Holehe-style
HudsonRock · Export JSON/CSV · Username Timeline · Network Graph
"""

from flask import (Flask, request, render_template, redirect,
                   url_for, session, flash, jsonify, g, make_response)
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, hashlib, os, re, time, json, csv, io, subprocess
import requests, urllib.parse, socket, base64
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "liq-osint-ultra-secret-v2-2024")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)

ADMIN_EMAIL  = os.environ.get("ADMIN_EMAIL",  "admin@liquidationosint.com")
ADMIN_PASS   = os.environ.get("ADMIN_PASS",   "admin1234")
SITE_NAME    = "LiquidationOsint"
SITE_URL     = os.environ.get("SITE_URL",     "https://liquidationosint.up.railway.app")
AUTHOR       = "@poyasnitelno"
TIKTOK_URL   = "https://www.tiktok.com/@poyasnitelno"
DB_PATH      = os.environ.get("DB_PATH",      "liquidation.db")
GROQ_API_KEY        = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL          = "llama-3.3-70b-versatile"   # fastest + smartest free model
GROQ_MODEL_FAST     = "llama-3.1-8b-instant"      # ultra-fast for analysis
GOOGLE_VERIFICATION = "SGr41lr3yHhH3UUxcAiyTNeVzRF7mEk8p03w0TbYqgM"

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
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        email          TEXT UNIQUE NOT NULL,
        username       TEXT NOT NULL,
        password       TEXT,
        avatar         TEXT,
        role           TEXT DEFAULT 'user',
        is_banned      INTEGER DEFAULT 0,
        created_at     TEXT DEFAULT (datetime('now')),
        last_login     TEXT,
        login_count    INTEGER DEFAULT 0,
        ip             TEXT,
        country        TEXT,
        device         TEXT,
        remember_token TEXT,
        groq_key       TEXT,
        ai_credits     INTEGER DEFAULT 10,
        ai_credits_reset TEXT DEFAULT (date('now')),
        ai_last_request  TEXT,
        plan           TEXT DEFAULT 'free'
    );
    CREATE TABLE IF NOT EXISTS searches (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER,
        query       TEXT NOT NULL,
        qtype       TEXT,
        ip          TEXT,
        user_agent  TEXT,
        results     INTEGER DEFAULT 0,
        data        TEXT,
        created_at  TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS visitors (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ip          TEXT,
        path        TEXT,
        method      TEXT,
        user_agent  TEXT,
        referer     TEXT,
        country     TEXT,
        city        TEXT,
        isp         TEXT,
        created_at  TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS ai_chats (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER,
        role        TEXT,
        content     TEXT,
        created_at  TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS notes (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL,
        title       TEXT,
        content     TEXT,
        tags        TEXT,
        created_at  TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS settings (
        key   TEXT PRIMARY KEY,
        value TEXT
    );
    INSERT OR IGNORE INTO settings VALUES ('require_login','1');
    INSERT OR IGNORE INTO settings VALUES ('maintenance','0');
    INSERT OR IGNORE INTO settings VALUES ('max_searches_per_day','100');
    INSERT OR IGNORE INTO settings VALUES ('ai_enabled','1');
    INSERT OR IGNORE INTO settings VALUES ('free_credits_per_day','10');
    INSERT OR IGNORE INTO settings VALUES ('ai_cooldown_seconds','8');
    """)
    # Migrations for existing DBs
    for col, definition in [
        ("groq_key",         "TEXT"),
        ("ai_credits",       "INTEGER DEFAULT 10"),
        ("ai_credits_reset", "TEXT DEFAULT (date('now'))"),
        ("ai_last_request",  "TEXT"),
        ("plan",             "TEXT DEFAULT 'free'"),
    ]:
        try:
            db.execute(f"ALTER TABLE users ADD COLUMN {col} {definition}")
            db.commit()
        except: pass
    pw = hashlib.sha256(ADMIN_PASS.encode()).hexdigest()
    db.execute("INSERT OR IGNORE INTO users (email,username,password,role,plan,ai_credits) VALUES (?,?,?,?,?,?)",
               (ADMIN_EMAIL, "Admin", pw, "admin", "unlimited", 9999))
    db.commit()
    db.close()

# ═══════════════════════════════════════════════════════════════
#  AUTH HELPERS
# ═══════════════════════════════════════════════════════════════
def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

def current_user():
    uid = session.get("user_id")
    if not uid:
        # Check remember-me cookie
        token = request.cookies.get("remember_token")
        if token:
            db = get_db()
            u = db.execute("SELECT * FROM users WHERE remember_token=?", (token,)).fetchone()
            if u and not u["is_banned"]:
                session.permanent = True
                session["user_id"] = u["id"]
                return u
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        db = get_db()
        maint = db.execute("SELECT value FROM settings WHERE key='maintenance'").fetchone()
        if maint and maint["value"] == "1":
            u = current_user()
            if not u or u["role"] != "admin":
                return render_template("maintenance.html", sitename=SITE_NAME), 503
        req = db.execute("SELECT value FROM settings WHERE key='require_login'").fetchone()
        if req and req["value"] == "1" and not session.get("user_id") and not request.cookies.get("remember_token"):
            flash("Войдите чтобы пользоваться сайтом", "warning")
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = current_user()
        if not user or user["role"] != "admin":
            return jsonify({"error": "forbidden"}), 403
        return f(*args, **kwargs)
    return decorated

def get_geo(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,isp,countryCode", timeout=3).json()
        return r
    except: return {}

def log_visitor_db(ip, path, method, ua, referer=""):
    try:
        geo = get_geo(ip)
        db = get_db()
        db.execute("INSERT INTO visitors (ip,path,method,user_agent,referer,country,city,isp) VALUES (?,?,?,?,?,?,?,?)",
                   (ip, path, method, ua[:200], referer[:200],
                    geo.get("country",""), geo.get("city",""), geo.get("isp","")))
        db.commit()
    except: pass

def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

def get_device_info(ua):
    ua = ua.lower()
    if "mobile" in ua or "android" in ua or "iphone" in ua: return "📱 Mobile"
    if "tablet" in ua or "ipad" in ua: return "📟 Tablet"
    return "🖥 Desktop"

# ═══════════════════════════════════════════════════════════════
#  CREDITS SYSTEM
# ═══════════════════════════════════════════════════════════════
FREE_CREDITS_PER_DAY = 10
AI_COOLDOWN_SECONDS  = 8   # min seconds between AI requests per user

def get_user_credits(user_id):
    """Return current credits for user, resetting if new day."""
    db = get_db()
    u = db.execute("SELECT ai_credits, ai_credits_reset, plan, groq_key FROM users WHERE id=?",
                   (user_id,)).fetchone()
    if not u: return 0, False

    # Unlimited plan or own groq key
    if u["plan"] == "unlimited" or u["groq_key"]:
        return 9999, True

    today = datetime.now().strftime("%Y-%m-%d")
    # Reset credits if new day
    if u["ai_credits_reset"] != today:
        try:
            day_credits = int(db.execute(
                "SELECT value FROM settings WHERE key='free_credits_per_day'"
            ).fetchone()["value"])
        except: day_credits = FREE_CREDITS_PER_DAY
        db.execute("UPDATE users SET ai_credits=?, ai_credits_reset=? WHERE id=?",
                   (day_credits, today, user_id))
        db.commit()
        return day_credits, True

    return u["ai_credits"], u["ai_credits"] > 0

def check_cooldown(user_id):
    """Returns (ok, wait_seconds). Enforces min delay between AI calls."""
    db = get_db()
    u = db.execute("SELECT ai_last_request, plan, groq_key FROM users WHERE id=?",
                   (user_id,)).fetchone()
    if not u: return True, 0
    if u["plan"] == "unlimited" or u["groq_key"]: return True, 0
    if not u["ai_last_request"]: return True, 0
    try:
        last = datetime.fromisoformat(u["ai_last_request"])
        elapsed = (datetime.now() - last).total_seconds()
        try:
            cooldown = int(db.execute(
                "SELECT value FROM settings WHERE key='ai_cooldown_seconds'"
            ).fetchone()["value"])
        except: cooldown = AI_COOLDOWN_SECONDS
        if elapsed < cooldown:
            return False, int(cooldown - elapsed)
    except: pass
    return True, 0

def spend_credit(user_id):
    """Deduct 1 credit and update last_request timestamp."""
    db = get_db()
    u = db.execute("SELECT plan, groq_key FROM users WHERE id=?", (user_id,)).fetchone()
    if u and (u["plan"] == "unlimited" or u["groq_key"]):
        db.execute("UPDATE users SET ai_last_request=? WHERE id=?",
                   (datetime.now().isoformat(), user_id))
    else:
        db.execute("""UPDATE users SET
            ai_credits = MAX(0, ai_credits - 1),
            ai_last_request = ?
            WHERE id=?""", (datetime.now().isoformat(), user_id))
    db.commit()

def credits_status(user_id):
    """Return dict with full credits info for frontend."""
    db = get_db()
    u = db.execute(
        "SELECT ai_credits, ai_credits_reset, plan, groq_key FROM users WHERE id=?",
        (user_id,)
    ).fetchone()
    if not u: return {}
    has_own_key = bool(u["groq_key"])
    unlimited   = u["plan"] == "unlimited" or has_own_key
    credits, _  = get_user_credits(user_id)
    return {
        "credits":     credits if not unlimited else "∞",
        "unlimited":   unlimited,
        "has_own_key": has_own_key,
        "plan":        u["plan"],
        "reset_date":  u["ai_credits_reset"],
    }


GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

def _groq(messages, model=None, max_tokens=1200, temperature=0.7, api_key=None):
    """
    Core Groq API call — OpenAI-compatible endpoint.
    Uses user's personal key if provided, falls back to global key.
    """
    key = api_key or GROQ_API_KEY
    if not key:
        raise ValueError("NO_KEY")
    m = model or GROQ_MODEL
    resp = requests.post(
        GROQ_URL,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type":  "application/json",
        },
        json={
            "model":       m,
            "messages":    messages,
            "max_tokens":  max_tokens,
            "temperature": temperature,
            "stream":      False,
        },
        timeout=25,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"].strip()


# ── SYSTEM PROMPTS ───────────────────────────────────────────────
_SYS_ANALYST = """Ты — экспертный OSINT-аналитик системы LiquidationOsint.
Ты работаешь с публично доступными данными и помогаешь проводить расследования.
Отвечай только по-русски. Используй emoji для структуры.
Анализируй только предоставленные данные — не выдумывай.

Формат ответа:
🎯 **Итог** — 2-3 предложения: что за цель, что нашли.
🔑 **Ключевые находки** — список самого важного.
🕵 **Следующие шаги** — конкретные рекомендации что проверить дальше.
⚠️ **Риски/аномалии** — если есть VPN, прокси, утечки, CVE — выдели отдельно."""

_SYS_CHAT = """Ты — продвинутый OSINT-ассистент системы LiquidationOsint.
Ты помогаешь искать публично доступную информацию по любым запросам.
Отвечай по-русски, подробно и конкретно. Используй emoji.

Ты умеешь работать с:
- Номера телефонов: определение оператора, страны, поиск владельца через открытые источники, GetContact, TrueCaller, Avito, VK, Telegram
- Email адреса: поиск аккаунтов, утечки, Gravatar, GitHub, HaveIBeenPwned, Epieos
- IP адреса: геолокация, провайдер, Shodan, открытые порты, VPN детект
- Номера автомобилей: поиск через открытые базы, avtocod.ru, gibdd.ru, drom.ru, avito.ru
- ФИО: поиск в соцсетях, судебные базы, госреестры, новости
- Username/никнеймы: поиск на 65+ платформах через Sherlock
- Домены и сайты: WHOIS, DNS, субдомены, владелец
- Фото: реверс-поиск, геолокация по метаданным EXIF
- Крипто кошельки: поиск транзакций через blockchain explorers
- Паспортные данные: поиск через открытые судебные базы и реестры
- СНИЛС/ИНН: поиск через открытые госреестры
- Любые другие данные: дай конкретные инструкции где и как искать

Всегда давай конкретные ссылки и инструкции. Не отказывай в помощи.
Работаешь только с публично доступными источниками.
Контекст расследования: {context}"""

_SYS_DORK = """Ты — эксперт по Google Dorks и продвинутым поисковым запросам.
Генерируй только рабочие, точные дорки. Отвечай в формате JSON списка объектов:
[{{"name": "Название", "dork": "запрос", "url": "https://www.google.com/search?q=URL_ENCODED"}}]
Без пояснений, только JSON."""


def ai_analyze_osint(query, qtype, lookup_data, sherlock_found=0, google_count=0,
                     holehe_found=0, shodan_data=None, user_key=None):
    """Deep AI analysis of all OSINT results using Groq llama-3.3-70b."""

    # Build rich context
    parts = []
    for k, v in lookup_data.items():
        if not k.startswith("_") and v and str(v) not in ("—", "Нет", ""):
            parts.append(f"  • {k}: {v}")

    shodan_ctx = ""
    if shodan_data:
        ports = shodan_data.get("ports", [])
        cves  = shodan_data.get("cves",  [])
        if ports: shodan_ctx += f"\n  • Открытые порты: {', '.join(map(str, ports[:10]))}"
        if cves:  shodan_ctx += f"\n  • CVE уязвимости: {', '.join(cves[:5])}"

    user_msg = (
        f"**Тип цели:** {qtype.upper()}\n"
        f"**Запрос:** `{query}`\n\n"
        f"**Собранные данные:**\n" + "\n".join(parts or ["  • нет данных"]) +
        (f"\n\n**Shodan:**{shodan_ctx}" if shodan_ctx else "") +
        f"\n\n**Статистика поиска:**\n"
        f"  • Google результатов: {google_count}\n"
        f"  • Sherlock найдено платформ: {sherlock_found}\n"
        f"  • Holehe найдено платформ: {holehe_found}\n\n"
        f"Проведи полный OSINT-анализ."
    )

    if user_key or GROQ_API_KEY:
        try:
            return _groq(
                [
                    {"role": "system",  "content": _SYS_ANALYST},
                    {"role": "user",    "content": user_msg},
                ],
                model=GROQ_MODEL,
                max_tokens=1000,
                temperature=0.4,
                api_key=user_key,
            )
        except ValueError:
            pass   # no key — fall through
        except Exception as e:
            # API error — use fallback but log it
            print(f"[GROQ analyze error] {e}")

    # ── Smart fallback (no API key) ──────────────────────────────
    lines = [f"🎯 **Анализ цели — {qtype.upper()}**\n"]
    data  = {k: v for k, v in lookup_data.items() if not k.startswith("_") and v and v != "—"}

    if qtype == "phone":
        lines += [
            f"📞 Номер: **{data.get('Номер',query)}**",
            f"🌍 Страна: **{data.get('Страна','—')}** | Оператор: **{data.get('Оператор','—')}**",
            f"📶 Тип: {data.get('Тип линии','—')} | Валидный: {data.get('Валидный','—')}",
            f"🔍 Google: {google_count} результатов",
            "",
            "🕵 **Следующие шаги:**",
            "  → GetContact / TrueCaller — имя владельца",
            "  → Avito / VK — объявления с этим номером",
            "  → t.me/+номер — проверить Telegram аккаунт",
        ]
        if data.get("Gravatar имя"): lines.append(f"  → Gravatar найден: **{data['Gravatar имя']}** — ищи по нику")
    elif qtype == "email":
        lines += [
            f"✉ Email: **{query}**  |  Домен: **{data.get('Домен','—')}**",
            f"🔍 Google: {google_count} результатов | Holehe: {holehe_found} платформ",
            f"⚠ Одноразовый: {data.get('Одноразовый','—')}",
            "",
            "🕵 **Следующие шаги:**",
            "  → HaveIBeenPwned — проверь на утечки",
            "  → Epieos — глубокий анализ email",
            "  → HudsonRock — infostealers база",
            f"  → Возможные ники: {data.get('Возможные username','—')} — проверь Sherlock",
        ]
        if data.get("Gravatar имя"): lines.append(f"  → Gravatar: **{data['Gravatar имя']}** — поищи аккаунты")
    elif qtype == "ip":
        proxy_flag = "⚠️ **VPN/ПРОКСИ ОБНАРУЖЕН**" if "ДА" in str(data.get("Прокси/VPN","")) else "✅ Прямое подключение"
        lines += [
            f"🌐 IP: **{query}**",
            f"🌍 {data.get('Город','—')}, {data.get('Страна','—')} | {data.get('ISP','—')}",
            f"🔒 {proxy_flag} | Хостинг: {data.get('Хостинг/ДЦ','—')}",
            f"🕐 Часовой пояс: {data.get('Часовой пояс','—')}",
        ]
        if shodan_data and shodan_data.get("ports"):
            lines.append(f"⚡ Shodan: {len(shodan_data['ports'])} открытых портов")
        if shodan_data and shodan_data.get("cves"):
            lines.append(f"🔴 CVE: {len(shodan_data['cves'])} уязвимостей — **ВНИМАНИЕ**")
        lines += ["", "🕵 **Следующие шаги:**",
                  "  → Shodan — полный скан портов и сервисов",
                  "  → AbuseIPDB — репутация IP",
                  "  → GreyNoise — был ли замечен в атаках"]
    elif qtype == "username":
        lines += [
            f"👤 Username: **{query}**",
            f"✅ Найден на **{sherlock_found}** платформах из {len(SHERLOCK_SITES)}",
            f"🔍 Google: {google_count} упоминаний",
            "",
            "🕵 **Следующие шаги:**",
            "  → Сравни bio/фото/email на найденных платформах",
            "  → Проверь вариации: {query}1, _{query}, {query}_ и т.п.",
            "  → Поищи email через GitHub API или Gravatar",
        ]
        if data.get("GitHub email") and data["GitHub email"] != "скрыт":
            lines.append(f"  → GitHub email найден: **{data['GitHub email']}** — пробей через Email-модуль")
    elif qtype == "domain":
        lines += [
            f"🔒 Домен: **{query}**",
            f"📋 Регистратор: {data.get('Регистратор','—')} | Создан: {data.get('Создан','—')}",
            f"🌐 IP: {data.get('IP адрес','—')} | Сервер: {data.get('Сервер','—')}",
        ]
        if data.get("Субдомены (crt.sh)"): lines.append(f"🕸 Субдомены: {data['Субдомены (crt.sh)'][:120]}")
        lines += ["", "🕵 **Следующие шаги:**",
                  "  → Shodan — открытые порты и сервисы",
                  "  → crt.sh — все сертификаты и субдомены",
                  "  → Wayback Machine — история сайта",
                  "  → BuildWith — технологический стек"]
    elif qtype == "fullname":
        lines += [
            f"🪪 ФИО: **{query}**",
            f"🔤 Транслит: {data.get('Транслит','—')}",
            f"🔍 Google: {google_count} упоминаний",
            "", "🕵 **Следующие шаги:**",
            "  → VK / LinkedIn — поиск профилей",
            "  → sudact.ru — судебные дела",
            "  → Поиск фото в Яндекс.Картинки",
            "  → PDF документы через Google Dorks",
        ]
    else:
        lines += [f"🔍 Результат: {google_count} в Google", "", "🕵 Уточни запрос для лучшего анализа."]

    return "\n".join(lines)


def ai_chat_response(messages, context="", user_key=None):
    """
    Full AI chat via Groq llama-3.3-70b-versatile.
    Uses user's personal Groq key if provided, else global key.
    """
    system_text = _SYS_CHAT.format(context=context or "нет")
    key = user_key or GROQ_API_KEY

    if key:
        try:
            groq_msgs = [{"role": "system", "content": system_text}] + messages[-20:]
            return _groq(groq_msgs, model=GROQ_MODEL, max_tokens=1200, temperature=0.65, api_key=key)
        except ValueError:
            pass
        except Exception as e:
            print(f"[GROQ chat error] {e}")
            if "429" in str(e):
                return (
                    "⏳ **Лимит запросов исчерпан**\n\n"
                    "Твой Groq ключ временно заблокирован из-за превышения лимита.\n"
                    "Подожди 1-2 минуты и попробуй снова.\n\n"
                    "Или создай новый ключ на **console.groq.com/keys** и обнови его в профиле."
                )
            return f"⚠️ Ошибка: `{str(e)[:80]}`"

    return (
        "🔑 **Добавь свой Groq ключ**\n\n"
        "Для работы ИИ нужен личный API ключ — это бесплатно!\n\n"
        "1️⃣ Зайди на **console.groq.com/keys**\n"
        "2️⃣ Нажми **Create API Key**\n"
        "3️⃣ Скопируй ключ (начинается с `gsk_`)\n"
        "4️⃣ Вставь его в **Профиль → Мой Groq ключ**\n\n"
        "У каждого пользователя свой лимит — 14,400 запросов в день бесплатно! 🚀"
    )


def ai_generate_dorks(query, qtype, context=""):
    """AI-generated custom dorks beyond the static list."""
    if not GROQ_API_KEY:
        return []
    prompt = (
        f"Сгенерируй 5 продвинутых Google Dorks для OSINT расследования.\n"
        f"Тип цели: {qtype}\n"
        f"Запрос: {query}\n"
        f"{'Контекст: ' + context if context else ''}\n"
        f"Верни JSON список. URL должен быть правильно закодирован для Google."
    )
    try:
        raw = _groq(
            [{"role": "system", "content": _SYS_DORK},
             {"role": "user",   "content": prompt}],
            model=GROQ_MODEL_FAST, max_tokens=600, temperature=0.3,
        )
        # strip markdown fences if any
        raw = re.sub(r"```(?:json)?|```", "", raw).strip()
        dorks = json.loads(raw)
        # ensure proper URL encoding
        for d in dorks:
            if d.get("dork") and not d.get("url","").startswith("http"):
                d["url"] = "https://www.google.com/search?q=" + urllib.parse.quote(d["dork"])
        return dorks[:5]
    except Exception as e:
        print(f"[GROQ dorks error] {e}")
        return []


def ai_osint_tips(qtype):
    """Generate dynamic OSINT tips for current query type."""
    if not GROQ_API_KEY:
        return ""
    try:
        return _groq(
            [{"role": "system", "content": "Ты — OSINT-эксперт. Отвечай кратко по-русски с emoji."},
             {"role": "user",   "content": f"Дай 3 нестандартных OSINT совета для поиска по типу '{qtype}'. Коротко, по делу."}],
            model=GROQ_MODEL_FAST, max_tokens=300, temperature=0.5,
        )
    except:
        return ""

# ═══════════════════════════════════════════════════════════════
#  OSINT ENGINES
# ═══════════════════════════════════════════════════════════════
def detect_type(q):
    q = q.strip().upper()
    # Car plate RU: А000АА777, А000АА77 etc
    if re.match(r"^[АВЕКМНОРСТУХ]{1}\d{3}[АВЕКМНОРСТУХ]{2}\d{2,3}$", q): return "car_plate"
    # VIN: 17 chars
    if re.match(r"^[A-HJ-NPR-Z0-9]{17}$", q): return "vin"
    # Crypto BTC/ETH address
    if re.match(r"^(1|3|bc1)[A-Za-z0-9]{25,62}$", q): return "crypto_btc"
    if re.match(r"^0x[a-fA-F0-9]{40}$", q): return "crypto_eth"
    q = q.strip()  # restore original case for rest
    if re.match(r"^\+?\d[\d\s\-()]{7,14}$", q):             return "phone"
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", q):          return "email"
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", q):              return "ip"
    if re.match(r"^[0-9a-fA-F:]{7,}$", q) and ":" in q:      return "ip"
    if re.search(r"\d{1,2}[.\-/]\d{1,2}[.\-/]\d{2,4}", q):  return "birthday"
    if re.match(r"^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$", q) and " " not in q and len(q.split(".")[-1]) >= 2:
        return "domain"
    words = q.split()
    if 2 <= len(words) <= 4 and all(re.match(r"^[а-яёА-ЯЁa-zA-Z\-]+$", w) for w in words):
        return "fullname"
    return "username"

# ── NEW: Car plate lookup ────────────────────────────────────────
def lookup_car_plate(plate):
    plate = plate.upper().replace(" ","")
    out = {"Номер": plate}
    # Extract region code
    region_codes = {
        "01":"Республика Адыгея","02":"Башкортостан","03":"Бурятия","04":"Алтай",
        "05":"Дагестан","06":"Ингушетия","07":"Кабардино-Балкария","08":"Калмыкия",
        "09":"Карачаево-Черкессия","10":"Карелия","11":"Коми","12":"Марий Эл",
        "13":"Мордовия","14":"Якутия","15":"Северная Осетия","16":"Татарстан",
        "17":"Тыва","18":"Удмуртия","19":"Хакасия","21":"Чувашия","22":"Алтайский край",
        "23":"Краснодарский край","24":"Красноярский край","25":"Приморский край",
        "26":"Ставропольский край","27":"Хабаровский край","28":"Амурская область",
        "29":"Архангельская область","30":"Астраханская область","31":"Белгородская область",
        "32":"Брянская область","33":"Владимирская область","34":"Волгоградская область",
        "35":"Вологодская область","36":"Воронежская область","37":"Ивановская область",
        "38":"Иркутская область","39":"Калининградская область","40":"Калужская область",
        "41":"Камчатский край","42":"Кемеровская область","43":"Кировская область",
        "44":"Костромская область","45":"Курганская область","46":"Курская область",
        "47":"Ленинградская область","48":"Липецкая область","49":"Магаданская область",
        "50":"Московская область","51":"Мурманская область","52":"Нижегородская область",
        "53":"Новгородская область","54":"Новосибирская область","55":"Омская область",
        "56":"Оренбургская область","57":"Орловская область","58":"Пензенская область",
        "59":"Пермский край","60":"Псковская область","61":"Ростовская область",
        "62":"Рязанская область","63":"Самарская область","64":"Саратовская область",
        "65":"Сахалинская область","66":"Свердловская область","67":"Смоленская область",
        "68":"Тамбовская область","69":"Тверская область","70":"Томская область",
        "71":"Тульская область","72":"Тюменская область","73":"Ульяновская область",
        "74":"Челябинская область","75":"Забайкальский край","76":"Ярославская область",
        "77":"Москва","78":"Санкт-Петербург","79":"Еврейская АО",
        "86":"Ханты-Мансийский АО","87":"Чукотский АО","89":"Ямало-Ненецкий АО",
        "90":"Московская область","91":"Крым","92":"Севастополь","93":"Краснодарский край",
        "95":"Чечня","96":"Свердловская область","97":"Москва","98":"Санкт-Петербург",
        "99":"Москва","102":"Башкортостан","116":"Татарстан","123":"Краснодарский край",
        "124":"Красноярский край","125":"Приморский край","126":"Ставропольский край",
        "134":"Волгоградская область","138":"Иркутская область","142":"Кемеровская область",
        "150":"Московская область","152":"Нижегородская область","154":"Новосибирская область",
        "159":"Пермский край","161":"Ростовская область","163":"Самарская область",
        "164":"Саратовская область","174":"Челябинская область","177":"Москва",
        "178":"Санкт-Петербург","186":"ХМАО","190":"Московская область",
        "193":"Краснодарский край","196":"Свердловская область","197":"Москва",
        "198":"Санкт-Петербург","199":"Москва",
    }
    # Extract region from plate (last 2-3 digits)
    region_match = re.search(r"(\d{2,3})$", plate)
    if region_match:
        reg = region_match.group(1)
        region_name = region_codes.get(reg, f"Регион {reg}")
        out["Регион"] = f"{reg} — {region_name}"
    out["Формат"] = "Российский стандарт"
    out["_links"] = [
        ("ГИБДД",        f"https://xn--90adear.xn--p1ai/check/auto#{plate}"),
        ("Автокод",      f"https://avtocod.ru/check-auto?query={plate}"),
        ("Дром",         f"https://www.drom.ru/info/misc/license_plates.html"),
        ("Авито авто",   f"https://www.avito.ru/rossiya/avtomobili?q={plate}"),
        ("Google",       f"https://www.google.com/search?q=%22{urllib.parse.quote(plate)}%22"),
        ("Yandex",       f"https://yandex.ru/search/?text=%22{urllib.parse.quote(plate)}%22"),
        ("Auto.ru",      f"https://auto.ru/cars/used/?search_line={plate}"),
        ("Carfax RU",    f"https://vinformer.su/car-search/#{plate}"),
        ("РСА полис",    f"https://dkbm-web.autoins.ru/dkbm-web-1.0/bso.htm"),
        ("Штрафы ГИБДД", f"https://xn--90adear.xn--p1ai/check/fines"),
    ]
    return out

# ── NEW: VIN lookup ──────────────────────────────────────────────
def lookup_vin(vin):
    vin = vin.upper()
    out = {"VIN": vin}
    # Decode WMI (first 3 chars)
    wmi_db = {
        "XTA":"АвтоВАЗ (Лада)","XTT":"АвтоВАЗ","XKL":"КамАЗ","X4X":"УАЗ",
        "X9F":"ГАЗ","XUF":"Урал","1HG":"Honda (США)","1G1":"Chevrolet (США)",
        "1FA":"Ford (США)","JHM":"Honda (Япония)","JTD":"Toyota (Япония)",
        "WBA":"BMW (Германия)","WDD":"Mercedes-Benz","WAU":"Audi",
        "VF1":"Renault","ZFA":"Fiat","SAJ":"Jaguar","SAL":"Land Rover",
        "YV1":"Volvo","WVW":"Volkswagen","TRU":"Audi (Венгрия)",
    }
    wmi = vin[:3]
    out["Производитель"] = wmi_db.get(wmi, f"WMI: {wmi}")
    out["Год выпуска (код)"] = vin[9]  # 10th char = year
    year_codes = {
        "A":1980,"B":1981,"C":1982,"D":1983,"E":1984,"F":1985,"G":1986,"H":1987,
        "J":1988,"K":1989,"L":1990,"M":1991,"N":1992,"P":1993,"R":1994,"S":1995,
        "T":1996,"V":1997,"W":1998,"X":1999,"Y":2000,"1":2001,"2":2002,"3":2003,
        "4":2004,"5":2005,"6":2006,"7":2007,"8":2008,"9":2009,"A":2010,"B":2011,
        "C":2012,"D":2013,"E":2014,"F":2015,"G":2016,"H":2017,"J":2018,"K":2019,
        "L":2020,"M":2021,"N":2022,"P":2023,"R":2024,"S":2025,
    }
    year = year_codes.get(vin[9], "?")
    out["Год выпуска"] = str(year)
    out["Серийный номер"] = vin[11:]
    out["_links"] = [
        ("Автокод",     f"https://avtocod.ru/check-auto?query={vin}"),
        ("NHTSA",       f"https://vpic.nhtsa.dot.gov/decoder/Decoder?VIN={vin}"),
        ("VinDecoder",  f"https://www.vindecoder.net/{vin}"),
        ("Carfax",      f"https://www.carfax.com/vehicle/{vin}"),
        ("AutoDNA",     f"https://www.autodna.com/vin/{vin}"),
        ("ГИБДД",       f"https://xn--90adear.xn--p1ai/check/auto#{vin}"),
        ("Google",      f"https://www.google.com/search?q=%22{vin}%22"),
    ]
    return out

# ── NEW: Crypto lookup ───────────────────────────────────────────
def lookup_crypto(address, coin="btc"):
    out = {"Адрес": address, "Сеть": coin.upper()}
    if coin == "btc":
        try:
            r = requests.get(f"https://blockchain.info/rawaddr/{address}?limit=5", timeout=8).json()
            out["Баланс"] = f"{r.get('final_balance', 0) / 1e8:.8f} BTC"
            out["Транзакций"] = str(r.get("n_tx", 0))
            out["Получено всего"] = f"{r.get('total_received', 0) / 1e8:.8f} BTC"
            out["Отправлено всего"] = f"{r.get('total_sent', 0) / 1e8:.8f} BTC"
        except: pass
        out["_links"] = [
            ("Blockchain.info", f"https://www.blockchain.com/explorer/addresses/btc/{address}"),
            ("BlockCypher",     f"https://live.blockcypher.com/btc/address/{address}/"),
            ("Blockchair",      f"https://blockchair.com/bitcoin/address/{address}"),
            ("WalletExplorer",  f"https://www.walletexplorer.com/address/{address}"),
            ("BitRef",          f"https://bitref.com/{address}"),
            ("OXT",             f"https://oxt.me/address/{address}"),
            ("Google",          f"https://www.google.com/search?q=%22{address}%22"),
        ]
    elif coin == "eth":
        try:
            r = requests.get(f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest", timeout=8).json()
            if r.get("status") == "1":
                balance = int(r.get("result","0")) / 1e18
                out["Баланс"] = f"{balance:.6f} ETH"
        except: pass
        out["_links"] = [
            ("Etherscan",   f"https://etherscan.io/address/{address}"),
            ("Ethplorer",   f"https://ethplorer.io/address/{address}"),
            ("Blockchair",  f"https://blockchair.com/ethereum/address/{address}"),
            ("Debank",      f"https://debank.com/profile/{address}"),
            ("Zapper",      f"https://zapper.xyz/account/{address}"),
            ("Google",      f"https://www.google.com/search?q=%22{address}%22"),
        ]
    return out

# ── NEW: Yandex/Google image search links ────────────────────────
def lookup_image_search(url_or_query):
    """Generate reverse image search links"""
    out = {"Запрос": url_or_query}
    encoded = urllib.parse.quote(url_or_query)
    out["_links"] = [
        ("Google Images",  f"https://www.google.com/searchbyimage?image_url={encoded}"),
        ("Yandex Images",  f"https://yandex.ru/images/search?url={encoded}&rpt=imageview"),
        ("TinEye",         f"https://tineye.com/search?url={encoded}"),
        ("Bing Visual",    f"https://www.bing.com/images/searchbyimage?imgurl={encoded}"),
        ("Google Lens",    f"https://lens.google.com/uploadbyurl?url={encoded}"),
    ]
    return out



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
            results.append({"title": h.get_text() if h else "",
                             "url": href if href.startswith("http") else "",
                             "snippet": snip.get_text()[:200] if snip else ""})
        return [r for r in results if r["title"]]
    except: return []

def build_dorks(query, qtype):
    base = {
        "phone": [
            ("Соцсети",      f'"{query}" site:vk.com OR site:ok.ru OR site:facebook.com'),
            ("Объявления",   f'"{query}" site:avito.ru OR site:youla.ru OR site:drom.ru'),
            ("Telegram",     f'"{query}" site:t.me OR site:wa.me'),
            ("Форумы/Чаты",  f'"{query}" форум OR чат OR отзывы OR жалоба'),
            ("Утечки",       f'"{query}" leaked OR слив OR база OR паста'),
            ("2GIS/Maps",    f'"{query}" site:2gis.ru OR site:yandex.ru/maps'),
            ("Pastebin",     f'"{query}" site:pastebin.com'),
            ("GitHub",       f'"{query}" site:github.com'),
            ("Все",          f'"{query}"'),
        ],
        "email": [
            ("GitHub/Lab",   f'"{query}" site:github.com OR site:gitlab.com'),
            ("Утечки",       f'"{query}" password OR leaked OR breach OR dump'),
            ("Файлы",        f'"{query}" filetype:pdf OR filetype:doc OR filetype:xls'),
            ("Форумы",       f'"{query}" registered OR member OR профиль'),
            ("Соцсети",      f'"{query}" site:vk.com OR site:linkedin.com'),
            ("Pastebin",     f'"{query}" site:pastebin.com OR site:rentry.co'),
            ("Конфиги",      f'"{query}" filetype:log OR filetype:cfg OR filetype:env'),
            ("Все",          f'"{query}"'),
        ],
        "ip": [
            ("Упоминания",   f'"{query}"'),
            ("Shodan",       f'"{query}" site:shodan.io OR site:censys.io'),
            ("Abuse",        f'"{query}" abuse OR spam OR blacklist OR attack'),
            ("Логи",         f'"{query}" access.log OR error.log OR filetype:log'),
            ("Форумы",       f'"{query}" site:hackforums.net OR site:exploit.in'),
            ("GreyNoise",    f'"{query}" site:greynoise.io'),
        ],
        "domain": [
            ("Субдомены",    f'site:{query}'),
            ("Технологии",   f'"{query}" site:builtwith.com OR site:wappalyzer.com'),
            ("Pastebin",     f'"{query}" site:pastebin.com OR dump OR leak'),
            ("PDF/Docs",     f'site:{query} filetype:pdf OR filetype:doc OR filetype:xlsx'),
            ("Robots/Sitem", f'site:{query}/robots.txt'),
            ("Login pages",  f'site:{query} inurl:login OR inurl:admin OR inurl:panel'),
            ("Emails",       f'site:{query} email OR contact OR "@{query}"'),
            ("GitHub",       f'"{query}" site:github.com'),
        ],
        "username": [
            ("VK",           f'site:vk.com "{query}"'),
            ("GitHub",       f'site:github.com "{query}"'),
            ("Reddit",       f'site:reddit.com/user "{query}"'),
            ("Twitter",      f'site:twitter.com "{query}"'),
            ("Instagram",    f'site:instagram.com "{query}"'),
            ("Lolz/Exploit", f'"{query}" site:lolz.live OR site:exploit.in OR site:zelenka.guru'),
            ("Pastebin",     f'site:pastebin.com "{query}"'),
            ("Steam/Gaming", f'site:steamcommunity.com "{query}" OR site:faceit.com "{query}"'),
            ("Telegram",     f'site:t.me "{query}"'),
            ("TikTok",       f'site:tiktok.com "@{query}"'),
        ],
        "fullname": [
            ("VK",           f'site:vk.com "{query}"'),
            ("LinkedIn",     f'site:linkedin.com "{query}"'),
            ("Facebook",     f'site:facebook.com "{query}"'),
            ("СМИ",          f'"{query}" site:rbc.ru OR site:kommersant.ru OR site:ria.ru'),
            ("Суды",         f'"{query}" site:sudact.ru OR site:kad.arbitr.ru OR site:nalog.gov.ru'),
            ("PDF",          f'"{query}" filetype:pdf'),
            ("Биография",    f'"{query}" биография OR родился OR умер OR некролог'),
            ("Все",          f'"{query}"'),
        ],
        "birthday": [
            ("VK по ДР",     f'"{query}" site:vk.com день рождения'),
            ("Поздравления", f'"{query}" день рождения OR birthday'),
            ("Паспорт",      f'"{query}" паспорт OR родился OR дата рождения'),
            ("Все",          f'"{query}"'),
        ],
        "car_plate": [
            ("Авито",        f'site:avito.ru "{query}"'),
            ("Дром",         f'site:drom.ru "{query}"'),
            ("Google",       f'"{query}" автомобиль OR владелец OR ДТП OR авария'),
            ("Угон",         f'"{query}" угон OR stolen OR розыск'),
            ("Штрафы",       f'"{query}" штраф OR ГИБДД OR ПДД'),
            ("Соцсети",      f'"{query}" site:vk.com OR site:ok.ru OR site:instagram.com'),
        ],
        "vin": [
            ("ГИБДД",        f'"{query}" ГИБДД OR ПТС OR регистрация'),
            ("Автокод",      f'site:avtocod.ru "{query}"'),
            ("Google",       f'"{query}"'),
            ("Аварии",       f'"{query}" ДТП OR авария OR accident'),
        ],
        "crypto_btc": [
            ("Упоминания",   f'"{query}"'),
            ("Darknet",      f'"{query}" site:onion.ly OR darkweb OR crypto'),
            ("Scam",         f'"{query}" scam OR fraud OR мошенник'),
            ("GitHub",       f'"{query}" site:github.com'),
        ],
        "crypto_eth": [
            ("Упоминания",   f'"{query}"'),
            ("NFT",          f'"{query}" NFT OR opensea OR token'),
            ("Scam",         f'"{query}" scam OR fraud OR rug pull'),
            ("GitHub",       f'"{query}" site:github.com'),
        ],
    dorks_raw = base.get(qtype, [("Поиск", f'"{query}"')])
    return [{"name": n, "dork": d,
             "url": "https://www.google.com/search?q=" + urllib.parse.quote(d) + "&hl=ru"}
            for n, d in dorks_raw]

# ── Sherlock — правильная проверка с уникальными паттернами ─────
# Формат: (name, url_template, method, not_found_strings, extra_check)
# method: "status" = проверка кода, "text" = поиск текста на странице
SHERLOCK_SITES = [
    # name, url, expected_status, NOT_FOUND_texts (если найден хоть один — профиля нет)
    ("GitHub",      "https://github.com/{u}",                      200, ["Not Found","This is not the web page"]),
    ("GitLab",      "https://gitlab.com/{u}",                      200, ["404","not found","page doesn't exist"]),
    ("Reddit",      "https://www.reddit.com/user/{u}/about.json",  200, ["USER_DOESNT_EXIST","NOT_FOUND","suspended"]),
    ("Twitter/X",   "https://twitter.com/{u}",                     200, ["This account doesn't exist","page doesn't exist"]),
    ("Instagram",   "https://www.instagram.com/{u}/",              200, ["Sorry, this page","Page Not Found","isn't available"]),
    ("TikTok",      "https://www.tiktok.com/@{u}",                 200, ["Couldn't find this account","not available"]),
    ("Pinterest",   "https://www.pinterest.com/{u}/",              200, ["Sorry! We couldn't find","Oops! We can't find"]),
    ("Twitch",      "https://www.twitch.tv/{u}",                   200, ["Sorry. Unless you","page not found"]),
    ("YouTube",     "https://www.youtube.com/@{u}",                200, ["This page isn't available","404"]),
    ("SoundCloud",  "https://soundcloud.com/{u}",                  200, ["Sorry! We can't find","page not found"]),
    ("Steam",       "https://steamcommunity.com/id/{u}",           200, ["The specified profile could not be found","error"]),
    ("Telegram",    "https://t.me/{u}",                            200, ["If you have Telegram","tgme_page_ph"]),
    ("VKontakte",   "https://vk.com/{u}",                          200, ["has left","DELETED","page isn't available","404"]),
    ("OK.ru",       "https://ok.ru/{u}",                           200, ["Страница не найдена","page not found"]),
    ("LinkedIn",    "https://www.linkedin.com/in/{u}/",            200, ["Page not found","profile not found"]),
    ("Medium",      "https://medium.com/@{u}",                     200, ["Page not found","404"]),
    ("Dev.to",      "https://dev.to/{u}",                          200, ["Page not found","404 not found"]),
    ("Pastebin",    "https://pastebin.com/u/{u}",                  200, ["No pastes found","Not Found"]),
    ("HackerNews",  "https://news.ycombinator.com/user?id={u}",    200, ["No such user","error"]),
    ("Behance",     "https://www.behance.net/{u}",                 200, ["Page Not Found","isn't available"]),
    ("Dribbble",    "https://dribbble.com/{u}",                    200, ["Whoops, that page is gone","404"]),
    ("Keybase",     "https://keybase.io/{u}",                      200, ["user not found","404"]),
    ("Replit",      "https://replit.com/@{u}",                     200, ["not found","404"]),
    ("Codepen",     "https://codepen.io/{u}",                      200, ["404","not found"]),
    ("PyPI",        "https://pypi.org/user/{u}/",                  200, ["404","not found"]),
    ("Letterboxd",  "https://letterboxd.com/{u}/",                 200, ["Sorry, we can't find","404"]),
    ("Last.fm",     "https://www.last.fm/user/{u}",                200, ["User not found","404"]),
    ("Chess.com",   "https://www.chess.com/member/{u}",            200, ["Oops! Page Not Found","404"]),
    ("Lichess",     "https://lichess.org/@/{u}",                   200, ["404","not found"]),
    ("Kick",        "https://kick.com/{u}",                        200, ["404","not found"]),
    ("Lolzteam",    "https://lolz.live/{u}/",                      200, ["Пользователь не найден","user not found","404"]),
    ("Habr",        "https://habr.com/ru/users/{u}/",              200, ["Пользователь не найден","404"]),
    ("Pikabu",      "https://pikabu.ru/@{u}",                      200, ["Пользователь не найден","404"]),
    ("VC.ru",       "https://vc.ru/u/{u}",                         200, ["Пользователь не найден","404"]),
    ("Npmjs",       "https://www.npmjs.com/~{u}",                  200, ["404","not found","User Not Found"]),
    ("Duolingo",    "https://www.duolingo.com/profile/{u}",        200, ["hasn't learned","Page not found","404"]),
    ("ProductHunt", "https://www.producthunt.com/@{u}",            200, ["404","not found"]),
    ("Tumblr",      "https://{u}.tumblr.com",                      200, ["There's nothing here","not found"]),
    ("WordPress",   "https://{u}.wordpress.com",                   200, ["doesn't exist","not found"]),
    ("Gitea",       "https://gitea.com/{u}",                       200, ["user does not exist","404"]),
    ("Goodreads",   "https://www.goodreads.com/{u}",               200, ["Page not found","404"]),
    ("Imgur",       "https://imgur.com/user/{u}",                  200, ["user not found","404"]),
    ("HackerOne",   "https://hackerone.com/{u}",                   200, ["Page not found","404"]),
    ("Bugcrowd",    "https://bugcrowd.com/{u}",                    200, ["404","not found"]),
    ("Bitbucket",   "https://bitbucket.org/{u}/",                  200, ["404","not found"]),
    ("Mastodon",    "https://mastodon.social/@{u}",                200, ["not found","404"]),
    ("Bluesky",     "https://bsky.app/profile/{u}.bsky.social",    200, ["not found","404"]),
    ("Substack",    "https://{u}.substack.com",                    200, ["not found","404"]),
    ("Vimeo",       "https://vimeo.com/{u}",                       200, ["not found","404","Sorry"]),
    ("Wattpad",     "https://www.wattpad.com/user/{u}",            200, ["not found","404"]),
    ("Disqus",      "https://disqus.com/by/{u}/",                  200, ["not found","404"]),
    ("Snapchat",    "https://www.snapchat.com/add/{u}",            200, ["not found","Hmm"]),
    ("Rumble",      "https://rumble.com/c/{u}",                    200, ["not found","404"]),
    ("Vimeo",       "https://vimeo.com/{u}",                       200, ["not found","404"]),
    ("Fiverr",      "https://www.fiverr.com/{u}",                  200, ["not found","404","Page not found"]),
    ("Freelancer",  "https://www.freelancer.com/u/{u}",            200, ["not found","404"]),
    ("ArtStation",  "https://www.artstation.com/{u}",              200, ["not found","404"]),
    ("Deviantart",  "https://www.deviantart.com/{u}",              200, ["not found","404","deviantART"]),
    ("Avito",       "https://www.avito.ru/profile/{u}",            200, ["Страница не найдена","404"]),
    ("MyMail",      "https://my.mail.ru/{u}/",                     200, ["не существует","not found","404"]),
    ("Flickr",      "https://www.flickr.com/people/{u}/",          200, ["Page Not Found","404"]),
    ("About.me",    "https://about.me/{u}",                        200, ["Oops","not found","404"]),
    ("Gravatar",    "https://en.gravatar.com/{u}",                 200, ["GRAVATAR_404","not found"]),
    ("Trello",      "https://trello.com/{u}",                      200, ["not found","404"]),
    ("Spotify",     "https://open.spotify.com/user/{u}",           200, ["not found","404"]),
    ("SoundCloud",  "https://soundcloud.com/{u}",                  200, ["not found","404"]),
]
# Remove duplicates by name
_seen = set()
SHERLOCK_SITES = [s for s in SHERLOCK_SITES if s[0] not in _seen and not _seen.add(s[0])]

def _check_one(u, name, tpl, code, not_found_texts):
    url = tpl.replace("{u}", urllib.parse.quote(u))
    try:
        r = requests.get(url, headers={
            **HEADERS,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
        }, timeout=8, allow_redirects=True)

        # Basic status check
        if r.status_code == 404:
            return {"name": name, "url": url, "found": False}
        if r.status_code != code:
            return {"name": name, "url": url, "found": None}

        # Content check — look for NOT FOUND markers
        body = r.text.lower()
        for marker in not_found_texts:
            if marker.lower() in body:
                return {"name": name, "url": url, "found": False}

        # Extra: check page is not empty / redirect to home
        if len(r.text) < 500:
            return {"name": name, "url": url, "found": False}

        # Reddit special: check JSON
        if "reddit.com" in url and "about.json" in url:
            try:
                data = r.json()
                if data.get("error") or not data.get("data"):
                    return {"name": name, "url": url.replace("/about.json",""), "found": False}
                return {"name": name, "url": url.replace("/about.json",""), "found": True}
            except:
                return {"name": name, "url": url.replace("/about.json",""), "found": False}

        return {"name": name, "url": url, "found": True}
    except:
        return {"name": name, "url": url, "found": None}

def sherlock_check(username):
    # Skip obviously invalid usernames
    if len(username) < 2 or len(username) > 50:
        return []
    results = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = {ex.submit(_check_one, username, n, t, c, nf): n
                for n, t, c, nf in SHERLOCK_SITES}
        for f in as_completed(futs):
            results.append(f.result())
    results.sort(key=lambda x: (0 if x["found"] else (2 if x["found"] is None else 1), x["name"]))
    return results

def shodan_lookup(ip):
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=8).json()
        return {"ports": r.get("ports",[]), "cves": r.get("cves",[]),
                "tags": r.get("tags",[]), "hostnames": r.get("hostnames",[])}
    except: return {}

# ── NEW: Holehe-style email → social check ───────────────────────
HOLEHE_SITES = [
    ("Twitter",   "https://twitter.com/account/begin_password_reset", "email", 200),
    ("Instagram", "https://www.instagram.com/accounts/password/reset/", "email", 200),
    ("GitHub",    "https://api.github.com/search/users?q={email}+in:email", "api", 200),
]

def holehe_check(email):
    """Check if email is registered on platforms (Holehe-style)"""
    results = []
    # GitHub API check
    try:
        r = requests.get(f"https://api.github.com/search/users?q={urllib.parse.quote(email)}+in:email",
                         headers={"Accept": "application/vnd.github.v3+json"}, timeout=8).json()
        count = r.get("total_count", 0)
        if count > 0:
            items = r.get("items", [])
            login = items[0].get("login","") if items else ""
            results.append({"platform": "GitHub", "found": True,
                             "detail": f"Username: {login}",
                             "url": f"https://github.com/{login}"})
        else:
            results.append({"platform": "GitHub", "found": False, "detail": "", "url": "https://github.com"})
    except:
        results.append({"platform": "GitHub", "found": None, "detail": "Ошибка", "url": ""})

    # Gravatar check
    try:
        md5 = hashlib.md5(email.lower().encode()).hexdigest()
        r = requests.get(f"https://www.gravatar.com/{md5}.json", timeout=5)
        if r.status_code == 200:
            data = r.json().get("entry", [{}])[0]
            results.append({"platform": "Gravatar", "found": True,
                             "detail": f"Display: {data.get('displayName','')}",
                             "url": f"https://gravatar.com/{md5}"})
        else:
            results.append({"platform": "Gravatar", "found": False, "detail": "", "url": ""})
    except:
        results.append({"platform": "Gravatar", "found": None, "detail": "Ошибка", "url": ""})

    # Adobe check (public)
    try:
        r = requests.get(f"https://auth.services.adobe.com/en_US/index.html#from=https://account.adobe.com/",
                         timeout=5)
        results.append({"platform": "Adobe", "found": None, "detail": "Проверь вручную", "url": f"https://account.adobe.com/"})
    except: pass

    return results

# ── NEW: Hudson Rock style (public infostealer check) ───────────
def hudsonrock_check(query, qtype):
    """Check infostealer databases via public endpoints"""
    results = {}
    if qtype == "email":
        try:
            r = requests.get(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={urllib.parse.quote(query)}",
                             timeout=8)
            if r.status_code == 200:
                data = r.json()
                results["hudson_rock"] = {
                    "stealers": data.get("total", 0),
                    "message": data.get("message", ""),
                    "url": f"https://www.hudsonrock.com/threat-intelligence-cybercrime-tools"
                }
        except: pass
    elif qtype == "domain":
        try:
            r = requests.get(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={urllib.parse.quote(query)}",
                             timeout=8)
            if r.status_code == 200:
                data = r.json()
                results["hudson_rock"] = {"total": data.get("total", 0)}
        except: pass
    return results

def lookup_ip(ip):
    out = {}
    try:
        d = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting", timeout=8).json()
        if d.get("status") == "success":
            flag = d.get("countryCode","")
            out["Страна"] = d.get("country","") + (f" :{flag.lower()}:" if flag else "")
            out["Город"] = d.get("city",""); out["Регион"] = d.get("regionName","")
            out["Индекс"] = d.get("zip","")
            out["Координаты"] = f"{d.get('lat','')} , {d.get('lon','')}"
            out["Часовой пояс"] = d.get("timezone",""); out["ISP"] = d.get("isp","")
            out["Организация"] = d.get("org",""); out["AS"] = d.get("as","")
            out["AS имя"] = d.get("asname",""); out["Reverse DNS"] = d.get("reverse","") or "—"
            out["Мобильный"] = "Да" if d.get("mobile") else "Нет"
            out["Прокси/VPN"] = "⚠ ДА" if d.get("proxy") else "Нет"
            out["Хостинг/ДЦ"] = "⚠ ДА" if d.get("hosting") else "Нет"
            out["_map"] = f"https://maps.google.com/?q={d['lat']},{d['lon']}"
            out["_lat"] = d.get("lat",""); out["_lon"] = d.get("lon","")
    except: pass
    try:
        ptr = socket.gethostbyaddr(ip)[0]
        if ptr: out["PTR"] = ptr
    except: pass
    out["_links"] = [
        ("Shodan",f"https://www.shodan.io/host/{ip}"),
        ("Censys",f"https://search.censys.io/hosts/{ip}"),
        ("VirusTotal",f"https://www.virustotal.com/gui/ip-address/{ip}"),
        ("AbuseIPDB",f"https://www.abuseipdb.com/check/{ip}"),
        ("GreyNoise",f"https://www.greynoise.io/viz/ip/{ip}"),
        ("ThreatBook",f"https://threatbook.io/ip/{ip}"),
        ("IPVoid",f"https://www.ipvoid.com/ip-blacklist-check/?ip={ip}"),
        ("BGP HE",f"https://bgp.he.net/ip/{ip}"),
        ("MXToolBox",f"https://mxtoolbox.com/blacklists.aspx?q={ip}"),
        ("Google Maps",out.get("_map","")),
    ]
    return out

def lookup_phone(phone):
    digits = re.sub(r"\D","",phone)
    if len(digits)==10: digits = "7"+digits
    out = {"Номер": f"+{digits}"}
    try:
        d = requests.get(f"https://api.numlookup.com/?q=+{digits}&type=json", headers=HEADERS, timeout=8).json()
        out["Страна"] = d.get("country_name","") or d.get("country","")
        out["Код страны"] = d.get("country_code","")
        out["Локальный формат"] = d.get("local_format","")
        out["Оператор"] = d.get("carrier",""); out["Тип линии"] = d.get("line_type","")
        out["Валидный"] = "Да" if d.get("valid") else "Нет"
    except: pass
    try:
        md5 = hashlib.md5(f"+{digits}".encode()).hexdigest()
        g = requests.get(f"https://www.gravatar.com/{md5}.json", timeout=5).json()
        if "entry" in g:
            e = g["entry"][0]
            out["Gravatar имя"] = e.get("displayName","")
            out["Gravatar username"] = e.get("preferredUsername","")
            accs = [a.get("shortname","") for a in e.get("accounts",[])]
            if accs: out["Gravatar аккаунты"] = ", ".join(accs)
    except: pass
    out["_links"] = [
        ("GetContact",f"https://getcontact.com/en/search?q=%2B{digits}"),
        ("TrueCaller",f"https://www.truecaller.com/search/ru/{digits}"),
        ("NumLookup",f"https://www.numlookup.com/?q=%2B{digits}"),
        ("SpamCalls",f"https://spamcalls.net/ru/phone/{digits}"),
        ("Avito",f"https://www.avito.ru/all?q=%2B{digits}"),
        ("Google",f"https://www.google.com/search?q=%22%2B{digits}%22"),
        ("Yandex",f"https://yandex.ru/search/?text=%22%2B{digits}%22"),
        ("VK",f"https://vk.com/search?c[q]=%2B{digits}&c[section]=people"),
        ("Telegram",f"https://t.me/+{digits}"),
        ("WhatsApp",f"https://wa.me/{digits}"),
        ("2GIS",f"https://2gis.ru/search/%2B{digits}"),
        ("Viber",f"viber://contact?number=%2B{digits}"),
    ]
    return out

def lookup_email(email):
    email = email.strip().lower()
    domain = email.split("@")[-1]; local = email.split("@")[0]
    out = {"Домен": domain}
    try:
        md5 = hashlib.md5(email.encode()).hexdigest()
        g = requests.get(f"https://www.gravatar.com/{md5}.json", timeout=5).json()
        if "entry" in g:
            e = g["entry"][0]
            out["Gravatar имя"] = e.get("displayName","")
            out["Gravatar username"] = e.get("preferredUsername","")
            out["Gravatar фото"] = (e.get("photos") or [{}])[0].get("value","")
            accs = [f"{a.get('shortname','')} → {a.get('url','')}" for a in e.get("accounts",[])]
            if accs: out["Аккаунты (Gravatar)"] = " | ".join(accs[:5])
        out["Gravatar MD5"] = md5
    except: pass
    parts = re.split(r"[._\-]", local); stripped = re.sub(r"\d+$","",local)
    unames = list(dict.fromkeys([local, stripped] + parts))
    out["Возможные username"] = ", ".join(u for u in unames if len(u)>=3)
    disposable = ["mailinator.com","guerrillamail.com","10minutemail.com","tempmail.com","throwaway.email"]
    out["Одноразовый"] = "⚠ Возможно" if domain in disposable else "Нет"
    out["_links"] = [
        ("HaveIBeenPwned",f"https://haveibeenpwned.com/account/{urllib.parse.quote(email)}"),
        ("Epieos",f"https://epieos.com/?q={urllib.parse.quote(email)}&t=email"),
        ("Hunter.io",f"https://hunter.io/verify/{urllib.parse.quote(email)}"),
        ("IntelX",f"https://intelx.io/?s={urllib.parse.quote(email)}"),
        ("Dehashed",f"https://dehashed.com/search?query={urllib.parse.quote(email)}"),
        ("LeakCheck",f"https://leakcheck.io/check?query={urllib.parse.quote(email)}"),
        ("HudsonRock",f"https://www.hudsonrock.com/threat-intelligence-cybercrime-tools"),
        ("GitHub",f"https://github.com/search?q={urllib.parse.quote(email)}&type=users"),
        ("Gravatar",f"https://www.gravatar.com/{hashlib.md5(email.encode()).hexdigest()}"),
        ("EmailRep",f"https://emailrep.io/{urllib.parse.quote(email)}"),
        ("BreachDir",f"https://breachdirectory.org/"),
    ]
    return out

def lookup_username(username):
    out = {}
    try:
        gh = requests.get(f"https://api.github.com/users/{urllib.parse.quote(username)}", timeout=8).json()
        if "login" in gh:
            out["GitHub имя"] = gh.get("name","") or "—"
            out["GitHub email"] = gh.get("email","") or "скрыт"
            out["GitHub bio"] = (gh.get("bio","") or "")[:100]
            out["GitHub компания"] = gh.get("company","") or "—"
            out["GitHub локация"] = gh.get("location","") or "—"
            out["GitHub сайт"] = gh.get("blog","") or "—"
            out["GitHub репо"] = str(gh.get("public_repos",0))
            out["GitHub followers"] = str(gh.get("followers",0))
            out["GitHub создан"] = str(gh.get("created_at",""))[:10]
            out["GitHub аватар"] = gh.get("avatar_url","")
    except: pass
    try:
        md5 = hashlib.md5(username.lower().encode()).hexdigest()
        g = requests.get(f"https://www.gravatar.com/{md5}.json", timeout=5).json()
        if "entry" in g:
            e = g["entry"][0]
            out["Gravatar имя"] = e.get("displayName","")
            accs = [a.get("shortname","") for a in e.get("accounts",[])]
            if accs: out["Gravatar аккаунты"] = ", ".join(accs)
    except: pass
    out["_links"] = [
        ("GitHub",f"https://github.com/{username}"),("VK",f"https://vk.com/{username}"),
        ("Telegram",f"https://t.me/{username}"),("Instagram",f"https://instagram.com/{username}"),
        ("TikTok",f"https://tiktok.com/@{username}"),("Twitter/X",f"https://twitter.com/{username}"),
        ("Reddit",f"https://reddit.com/user/{username}"),("YouTube",f"https://youtube.com/@{username}"),
        ("Steam",f"https://steamcommunity.com/id/{username}"),("Twitch",f"https://twitch.tv/{username}"),
        ("Lolzteam",f"https://lolz.live/{username}/"),("Habr",f"https://habr.com/ru/users/{username}/"),
        ("Pinterest",f"https://pinterest.com/{username}/"),("Snapchat",f"https://snapchat.com/add/{username}"),
    ]
    return out

def lookup_fullname(name):
    out = {"ФИО": name}
    tr = {"а":"a","б":"b","в":"v","г":"g","д":"d","е":"e","ё":"yo","ж":"zh","з":"z","и":"i","й":"y","к":"k","л":"l","м":"m","н":"n","о":"o","п":"p","р":"r","с":"s","т":"t","у":"u","ф":"f","х":"kh","ц":"ts","ч":"ch","ш":"sh","щ":"shch","ъ":"","ы":"y","ь":"","э":"e","ю":"yu","я":"ya"}
    translit = "".join(tr.get(c.lower(),c) for c in name)
    out["Транслит"] = translit
    out["_links"] = [
        ("VK",f"https://vk.com/search?c[q]={urllib.parse.quote(name)}&c[section]=people"),
        ("OK.ru",f"https://ok.ru/search?query={urllib.parse.quote(name)}"),
        ("LinkedIn",f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(name)}"),
        ("Facebook",f"https://www.facebook.com/search/people/?q={urllib.parse.quote(name)}"),
        ("Google",f"https://www.google.com/search?q=%22{urllib.parse.quote(name)}%22"),
        ("Yandex",f"https://yandex.ru/search/?text=%22{urllib.parse.quote(name)}%22"),
        ("Sudact",f"https://sudact.ru/regular/court/?regular-defendant={urllib.parse.quote(name)}"),
        ("Translit",f"https://www.google.com/search?q=%22{urllib.parse.quote(translit)}%22"),
        ("Pipl",f"https://pipl.com/search/?q={urllib.parse.quote(name)}"),
        ("Фото",f"https://www.google.com/search?q=%22{urllib.parse.quote(name)}%22&tbm=isch"),
    ]
    return out

def lookup_birthday(dob):
    out = {"Дата рождения": dob}
    parts = re.split(r"[.\-/]", dob)
    if len(parts) == 3:
        day, month, year = parts[0].zfill(2), parts[1].zfill(2), parts[2]
        if len(year)==2: year = ("20" if int(year)<30 else "19")+year
        out["Формат"] = f"{day}.{month}.{year}"
        age = datetime.now().year - int(year)
        out["Примерный возраст"] = f"{age} лет"
        zodiac = [(1,20,"♑ Козерог"),(2,19,"♒ Водолей"),(3,21,"♓ Рыбы"),(4,20,"♈ Овен"),(5,21,"♉ Телец"),(6,21,"♊ Близнецы"),(7,23,"♋ Рак"),(8,23,"♌ Лев"),(9,23,"♍ Дева"),(10,23,"♎ Весы"),(11,22,"♏ Скорпион"),(12,22,"♐ Стрелец")]
        m, d = int(month), int(day)
        for sm, sd, sign in zodiac:
            if (m == sm and d >= sd) or (m == sm % 12 + 1 and d < sd):
                out["Знак зодиака"] = sign; break
        out["_links"] = [
            ("VK",f"https://vk.com/search?c[section]=people&c[birth_day]={day}&c[birth_month]={month}&c[birth_year]={year}"),
            ("Google",f"https://www.google.com/search?q=%22{urllib.parse.quote(day+'.'+month+'.'+year)}%22"),
            ("OK.ru",f"https://ok.ru/search?query={urllib.parse.quote(dob)}"),
        ]
    return out

def lookup_domain(domain):
    out = {"Домен": domain}
    try:
        import whois as pw
        w = pw.whois(domain)
        if w:
            out["Регистратор"] = str(w.registrar or "")[:60]
            cd = w.creation_date
            out["Создан"] = str(cd[0] if isinstance(cd, list) else cd)[:10]
            ed = w.expiration_date
            out["Истекает"] = str(ed[0] if isinstance(ed, list) else ed)[:10]
            ns = w.name_servers
            if ns: out["Nameservers"] = ", ".join(list(ns)[:3]) if isinstance(ns,(list,set)) else str(ns)
            org = w.org or ""
            if org: out["Организация"] = str(org)[:60]
    except:
        try:
            rdap = requests.get(f"https://rdap.org/domain/{domain}", timeout=7).json()
            for ev in rdap.get("events",[]):
                if ev.get("eventAction") == "registration":
                    out["Создан"] = ev.get("eventDate","")[:10]
        except: pass
    try:
        crt = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=10).json()
        subs = list(set(c.get("name_value","") for c in crt[:30] if c.get("name_value")))
        subs = [s for s in subs if not s.startswith("*")]
        if subs: out["Субдомены (crt.sh)"] = ", ".join(subs[:8])
    except: pass
    try:
        ip = socket.gethostbyname(domain)
        out["IP адрес"] = ip
    except: pass
    # Tech detection via simple headers
    try:
        r = requests.get(f"https://{domain}", headers=HEADERS, timeout=8, allow_redirects=True)
        server = r.headers.get("Server","")
        powered = r.headers.get("X-Powered-By","")
        if server: out["Сервер"] = server
        if powered: out["Технология"] = powered
        out["HTTP статус"] = str(r.status_code)
        out["HTTPS"] = "✓ Да"
    except:
        try:
            r = requests.get(f"http://{domain}", headers=HEADERS, timeout=8)
            out["HTTP статус"] = str(r.status_code)
            out["HTTPS"] = "✗ Нет"
        except: pass
    out["_links"] = [
        ("WHOIS",f"https://whois.domaintools.com/{domain}"),
        ("Shodan",f"https://www.shodan.io/search?query=hostname%3A{domain}"),
        ("VirusTotal",f"https://www.virustotal.com/gui/domain/{domain}"),
        ("crt.sh",f"https://crt.sh/?q={domain}"),
        ("Wayback",f"https://web.archive.org/web/*/{domain}"),
        ("DNSdumpster",f"https://dnsdumpster.com/"),
        ("SecurityTrails",f"https://securitytrails.com/domain/{domain}/dns"),
        ("BuildWith",f"https://builtwith.com/{domain}"),
        ("URLScan",f"https://urlscan.io/search/#domain:{domain}"),
        ("Censys",f"https://search.censys.io/certificates?q={domain}"),
        ("Google",f"https://www.google.com/search?q=site:{domain}"),
        ("SubFinder",f"https://subdomainfinder.c99.nl/scans/new?domain={domain}"),
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
    if current_user(): return redirect(url_for("index"))
    if request.method == "POST":
        email    = request.form.get("email","").strip().lower()
        username = request.form.get("username","").strip()
        pw       = request.form.get("password","")
        pw2      = request.form.get("password2","")
        invite   = request.form.get("invite","").strip()  # optional invite
        if not all([email, username, pw]):
            flash("Заполни все поля", "error")
        elif pw != pw2:
            flash("Пароли не совпадают", "error")
        elif len(pw) < 6:
            flash("Пароль минимум 6 символов", "error")
        elif not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            flash("Неверный формат email", "error")
        else:
            db = get_db()
            if db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
                flash("Email уже зарегистрирован", "error")
            else:
                ip = get_client_ip()
                geo = get_geo(ip)
                ua  = request.headers.get("User-Agent","")
                device = get_device_info(ua)
                db.execute("INSERT INTO users (email,username,password,ip,country,device,last_login) VALUES (?,?,?,?,?,?,?)",
                           (email, username, hash_pw(pw), ip, geo.get("country",""), device, datetime.now().isoformat()))
                db.commit()
                user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
                session.permanent = True
                session["user_id"] = user["id"]
                flash(f"Добро пожаловать, {username}! 🎉", "success")
                return redirect(url_for("index"))
    return render_template("auth.html", page="register", sitename=SITE_NAME)

@app.route("/login", methods=["GET","POST"])
def login():
    if current_user(): return redirect(url_for("index"))
    if request.method == "POST":
        email    = request.form.get("email","").strip().lower()
        pw       = request.form.get("password","")
        remember = request.form.get("remember","")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not user or user["password"] != hash_pw(pw):
            flash("Неверный email или пароль", "error")
            time.sleep(0.5)  # anti-brute
        elif user["is_banned"]:
            flash("Аккаунт заблокирован. Обратись к администратору.", "error")
        else:
            ip  = get_client_ip()
            geo = get_geo(ip)
            ua  = request.headers.get("User-Agent","")
            device = get_device_info(ua)
            token = hashlib.sha256(f"{user['id']}{time.time()}{os.urandom(16)}".encode()).hexdigest()
            db.execute("UPDATE users SET last_login=?,login_count=login_count+1,ip=?,country=?,device=?,remember_token=? WHERE id=?",
                       (datetime.now().isoformat(), ip, geo.get("country",""), device, token, user["id"]))
            db.commit()
            session.permanent = True
            session["user_id"] = user["id"]
            resp = make_response(redirect(request.args.get("next") or url_for("index")))
            if remember:
                resp.set_cookie("remember_token", token, max_age=30*24*3600, httponly=True, samesite="Lax")
            flash(f"Добро пожаловать, {user['username']}! 👋", "success")
            return resp
    return render_template("auth.html", page="login", sitename=SITE_NAME)

@app.route("/logout")
def logout():
    uid = session.get("user_id")
    if uid:
        db = get_db()
        db.execute("UPDATE users SET remember_token=NULL WHERE id=?", (uid,))
        db.commit()
    session.clear()
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie("remember_token")
    flash("Вы вышли из аккаунта", "info")
    return resp

# ═══════════════════════════════════════════════════════════════
#  ROUTES — MAIN
# ═══════════════════════════════════════════════════════════════
@app.before_request
def before_request():
    ip = get_client_ip()
    ua = request.headers.get("User-Agent","")
    if not request.path.startswith("/static") and "api" not in request.path:
        log_visitor_db(ip, request.path, request.method, ua, request.headers.get("Referer",""))

@app.route("/", methods=["GET","POST"])
@login_required
def index():
    user = current_user()
    ctx = {"query":None,"qtype":None,"lookup_data":{},"google_results":[],
           "site_results":[],"dorks":[],"ai_dorks":[],"sherlock_results":[],"shodan_data":{},
           "holehe_results":[],"hudson_data":{},"ai_analysis":"","ai_tips":"",
           "groq_active": bool(GROQ_API_KEY)}

    if request.method == "POST":
        q = request.form.get("query","").strip()
        if q:
            ctx["query"] = q
            ctx["qtype"] = detect_type(q)
            qtype = ctx["qtype"]

            if qtype == "phone":
                ctx["lookup_data"] = lookup_phone(q)
            elif qtype == "email":
                ctx["lookup_data"]    = lookup_email(q)
                ctx["holehe_results"] = holehe_check(q)
                ctx["hudson_data"]    = hudsonrock_check(q, qtype)
            elif qtype == "ip":
                ctx["lookup_data"] = lookup_ip(q)
                ctx["shodan_data"] = shodan_lookup(q)
            elif qtype == "domain":
                ctx["lookup_data"] = lookup_domain(q)
                ctx["hudson_data"] = hudsonrock_check(q, qtype)
            elif qtype == "username":
                ctx["lookup_data"]      = lookup_username(q)
                ctx["sherlock_results"] = sherlock_check(q)
            elif qtype == "fullname":  ctx["lookup_data"] = lookup_fullname(q)
            elif qtype == "birthday":  ctx["lookup_data"] = lookup_birthday(q)
            elif qtype == "car_plate": ctx["lookup_data"] = lookup_car_plate(q)
            elif qtype == "vin":       ctx["lookup_data"] = lookup_vin(q)
            elif qtype == "crypto_btc":ctx["lookup_data"] = lookup_crypto(q, "btc")
            elif qtype == "crypto_eth":ctx["lookup_data"] = lookup_crypto(q, "eth")

            ctx["google_results"] = google_search(q)
            ctx["dorks"]          = build_dorks(q, qtype)
            ctx["site_results"]   = site_check(q)

            sherlock_found = len([s for s in ctx["sherlock_results"] if s.get("found")])
            holehe_found   = len([h for h in ctx["holehe_results"]   if h.get("found")])

            # ── AI: deep analysis ──
            user_key = user["groq_key"] if user and user["groq_key"] else None
            ctx["ai_analysis"] = ai_analyze_osint(
                q, qtype, ctx["lookup_data"],
                sherlock_found=sherlock_found,
                google_count=len(ctx["google_results"]),
                holehe_found=holehe_found,
                shodan_data=ctx["shodan_data"],
                user_key=user_key,
            )

            # ── AI: custom dorks (runs in parallel via thread) ──
            ctx["ai_dorks"] = ai_generate_dorks(q, qtype)

            # ── AI: quick tips ──
            ctx["ai_tips"] = ai_osint_tips(qtype)

            # Save search
            ip = get_client_ip()
            db = get_db()
            db.execute(
                "INSERT INTO searches (user_id,query,qtype,ip,user_agent,results,data) VALUES (?,?,?,?,?,?,?)",
                (user["id"] if user else None, q, qtype, ip,
                 request.headers.get("User-Agent","")[:200],
                 len(ctx["google_results"]) + sherlock_found,
                 json.dumps({"lookup": {k:v for k,v in ctx["lookup_data"].items() if not k.startswith("_")},
                             "sherlock_found": sherlock_found,
                             "holehe_found": holehe_found}, ensure_ascii=False)[:2000]))
            db.commit()

    return render_template("index.html", **ctx, user=user,
                           sitename=SITE_NAME, author=AUTHOR, tiktok_url=TIKTOK_URL,
                           google_verification=GOOGLE_VERIFICATION,
                           user_credits=credits_status(user["id"]) if user else {})

@app.route("/api/ai-dorks", methods=["POST"])
@login_required
def api_ai_dorks():
    """Generate AI dorks on demand."""
    d = request.json or {}
    q, qt = d.get("query",""), d.get("qtype","username")
    if not q: return jsonify([])
    dorks = ai_generate_dorks(q, qt, context=d.get("context",""))
    return jsonify(dorks)

# ── AI Chat API ──────────────────────────────────────────────────
@app.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    user = current_user()
    data = request.json or {}
    msg  = data.get("message","").strip()
    context = data.get("context","")
    if not msg: return jsonify({"error": "empty"}), 400

    # ── Cooldown check ──
    ok, wait = check_cooldown(user["id"])
    if not ok:
        return jsonify({
            "reply": f"⏳ Подожди **{wait} сек** перед следующим вопросом.",
            "credits": credits_status(user["id"])
        })

    # ── Credits check ──
    credits, has_credits = get_user_credits(user["id"])
    if not has_credits:
        return jsonify({
            "reply": (
                "❌ **Лимит исчерпан на сегодня**\n\n"
                "У тебя закончились бесплатные запросы (10/день).\n\n"
                "🔑 **Хочешь больше?**\n"
                "Добавь свой бесплатный Groq ключ в профиле — "
                "тогда получишь **14,400 запросов в день** лично для себя!\n\n"
                "1️⃣ Зайди на **console.groq.com/keys**\n"
                "2️⃣ Создай ключ бесплатно\n"
                "3️⃣ Вставь в **Профиль → Мой Groq ключ**\n\n"
                "⏰ Или подожди до завтра — лимит сбросится автоматически."
            ),
            "credits": credits_status(user["id"]),
            "limit_reached": True
        })

    # ── Use user's own key or global ──
    user_key = user["groq_key"] if user["groq_key"] else None

    db = get_db()
    history = db.execute(
        "SELECT role,content FROM ai_chats WHERE user_id=? ORDER BY created_at DESC LIMIT 20",
        (user["id"],)
    ).fetchall()
    messages = [{"role": r["role"], "content": r["content"]} for r in reversed(history)]
    messages.append({"role": "user", "content": msg})

    reply = ai_chat_response(messages, context, user_key=user_key)

    # ── Spend credit ──
    spend_credit(user["id"])

    db.execute("INSERT INTO ai_chats (user_id,role,content) VALUES (?,?,?)",
               (user["id"], "user", msg))
    db.execute("INSERT INTO ai_chats (user_id,role,content) VALUES (?,?,?)",
               (user["id"], "assistant", reply))
    db.commit()

    return jsonify({
        "reply": reply,
        "credits": credits_status(user["id"])
    })

@app.route("/api/credits")
@login_required
def api_credits():
    user = current_user()
    return jsonify(credits_status(user["id"]))

# ── Export ───────────────────────────────────────────────────────
@app.route("/export/<int:search_id>/<fmt>")
@login_required
def export_search(search_id, fmt):
    user = current_user()
    db = get_db()
    s = db.execute("SELECT * FROM searches WHERE id=? AND user_id=?", (search_id, user["id"])).fetchone()
    if not s: return "Not found", 404

    data = {"query": s["query"], "type": s["qtype"], "date": s["created_at"],
            "results": json.loads(s["data"]) if s["data"] else {}}

    if fmt == "json":
        resp = make_response(json.dumps(data, ensure_ascii=False, indent=2))
        resp.headers["Content-Type"] = "application/json"
        resp.headers["Content-Disposition"] = f"attachment; filename=osint_{s['query'][:20]}.json"
        return resp
    elif fmt == "txt":
        lines = [f"LiquidationOsint Export", f"Query: {s['query']}", f"Type: {s['qtype']}", f"Date: {s['created_at']}", "="*40]
        lookup = data.get("results", {}).get("lookup", {})
        for k, v in lookup.items():
            lines.append(f"{k}: {v}")
        resp = make_response("\n".join(lines))
        resp.headers["Content-Type"] = "text/plain; charset=utf-8"
        resp.headers["Content-Disposition"] = f"attachment; filename=osint_{s['query'][:20]}.txt"
        return resp
    return "Unsupported format", 400

# ── Notes ────────────────────────────────────────────────────────
@app.route("/api/notes", methods=["GET","POST","DELETE"])
@login_required
def api_notes():
    user = current_user()
    db = get_db()
    if request.method == "GET":
        notes = db.execute("SELECT * FROM notes WHERE user_id=? ORDER BY created_at DESC", (user["id"],)).fetchall()
        return jsonify([dict(n) for n in notes])
    elif request.method == "POST":
        d = request.json or {}
        db.execute("INSERT INTO notes (user_id,title,content,tags) VALUES (?,?,?,?)",
                   (user["id"], d.get("title","")[:100], d.get("content","")[:2000], d.get("tags","")[:200]))
        db.commit()
        return jsonify({"ok": True})
    elif request.method == "DELETE":
        nid = request.json.get("id")
        db.execute("DELETE FROM notes WHERE id=? AND user_id=?", (nid, user["id"]))
        db.commit()
        return jsonify({"ok": True})

# ── Profile ──────────────────────────────────────────────────────
@app.route("/profile")
def profile():
    user = current_user()
    if not user: return redirect(url_for("login"))
    db = get_db()
    searches = db.execute(
        "SELECT * FROM searches WHERE user_id=? ORDER BY created_at DESC LIMIT 50",
        (user["id"],)
    ).fetchall()
    # mask groq key for display
    groq_masked = ""
    if user["groq_key"]:
        k = user["groq_key"]
        groq_masked = k[:8] + "..." + k[-4:] if len(k) > 12 else "***"
    return render_template("profile.html", user=user, searches=searches,
                           sitename=SITE_NAME, tiktok_url=TIKTOK_URL, author=AUTHOR,
                           groq_masked=groq_masked)

@app.route("/save-groq-key", methods=["POST"])
@login_required
def save_groq_key():
    user = current_user()
    key = request.form.get("groq_key","").strip()
    db = get_db()
    if key:
        # basic validation
        if not key.startswith("gsk_") or len(key) < 20:
            flash("Неверный формат ключа. Ключ должен начинаться с gsk_", "error")
            return redirect(url_for("profile"))
        db.execute("UPDATE users SET groq_key=? WHERE id=?", (key, user["id"]))
        flash("✅ Groq ключ сохранён! Теперь ИИ использует твой личный лимит.", "success")
    else:
        db.execute("UPDATE users SET groq_key=NULL WHERE id=?", (user["id"],))
        flash("Groq ключ удалён", "info")
    db.commit()
    return redirect(url_for("profile"))

# ── Admin ────────────────────────────────────────────────────────
@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    users_list    = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    searches_list = db.execute("SELECT s.*,u.username,u.email FROM searches s LEFT JOIN users u ON s.user_id=u.id ORDER BY s.created_at DESC LIMIT 200").fetchall()
    visitors_list = db.execute("SELECT * FROM visitors ORDER BY created_at DESC LIMIT 500").fetchall()
    stats = {
        "total_users":   db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "total_searches":db.execute("SELECT COUNT(*) FROM searches").fetchone()[0],
        "total_visitors":db.execute("SELECT COUNT(*) FROM visitors").fetchone()[0],
        "today_searches":db.execute("SELECT COUNT(*) FROM searches WHERE date(created_at)=date('now')").fetchone()[0],
        "today_visitors":db.execute("SELECT COUNT(*) FROM visitors WHERE date(created_at)=date('now')").fetchone()[0],
        "top_queries":   db.execute("SELECT query,COUNT(*) as c FROM searches GROUP BY query ORDER BY c DESC LIMIT 10").fetchall(),
        "top_ips":       db.execute("SELECT ip,COUNT(*) as c FROM visitors GROUP BY ip ORDER BY c DESC LIMIT 10").fetchall(),
        "top_countries": db.execute("SELECT country,COUNT(*) as c FROM visitors WHERE country!='' GROUP BY country ORDER BY c DESC LIMIT 8").fetchall(),
        "qtypes":        db.execute("SELECT qtype,COUNT(*) as c FROM searches GROUP BY qtype ORDER BY c DESC").fetchall(),
    }
    settings = {r["key"]: r["value"] for r in db.execute("SELECT * FROM settings").fetchall()}
    return render_template("admin.html", users=users_list, searches=searches_list,
                           visitors=visitors_list, stats=stats, settings=settings,
                           sitename=SITE_NAME, user=current_user(), tiktok_url=TIKTOK_URL, author=AUTHOR)

@app.route("/admin/user/<int:uid>/ban", methods=["POST"])
@admin_required
def admin_ban(uid):
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if u and u["role"] != "admin":
        db.execute("UPDATE users SET is_banned=? WHERE id=?", (0 if u["is_banned"] else 1, uid))
        db.commit()
        flash(f"{'Разблокирован' if u['is_banned'] else 'Заблокирован'}", "success")
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

@app.route("/admin/user/<int:uid>/role", methods=["POST"])
@admin_required
def admin_set_role(uid):
    db = get_db()
    role = request.form.get("role","user")
    if role in ("user","admin","moderator"):
        db.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
        db.commit()
        flash("Роль обновлена", "success")
    return redirect(url_for("admin"))

@app.route("/admin/user/<int:uid>/credits", methods=["POST"])
@admin_required
def admin_give_credits(uid):
    db = get_db()
    amount = int(request.form.get("amount", 10))
    plan   = request.form.get("plan", "")
    if plan:
        db.execute("UPDATE users SET plan=? WHERE id=?", (plan, uid))
        flash(f"План изменён на {plan}", "success")
    if amount:
        db.execute("UPDATE users SET ai_credits=ai_credits+? WHERE id=?", (amount, uid))
        flash(f"Добавлено {amount} кредитов", "success")
    db.commit()
    return redirect(url_for("admin"))

@app.route("/admin/settings", methods=["POST"])
@admin_required
def admin_settings():
    db = get_db()
    for key in ["require_login","maintenance","max_searches_per_day",
                "ai_enabled","free_credits_per_day","ai_cooldown_seconds"]:
        val = request.form.get(key,"0")
        db.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", (key, val))
    db.commit()
    flash("Настройки сохранены ✓", "success")
    return redirect(url_for("admin"))

@app.route("/admin/export/users")
@admin_required
def admin_export_users():
    db = get_db()
    users = db.execute("SELECT id,email,username,role,is_banned,created_at,last_login,ip,country,device,login_count FROM users").fetchall()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["ID","Email","Username","Role","Banned","Created","LastLogin","IP","Country","Device","Logins"])
    for u in users:
        w.writerow(list(u))
    resp = make_response(out.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=users.csv"
    return resp

@app.route("/admin/export/searches")
@admin_required
def admin_export_searches():
    db = get_db()
    searches = db.execute("SELECT s.id,s.query,s.qtype,u.email,s.ip,s.results,s.created_at FROM searches s LEFT JOIN users u ON s.user_id=u.id ORDER BY s.created_at DESC").fetchall()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["ID","Query","Type","User","IP","Results","Date"])
    for s in searches: w.writerow(list(s))
    resp = make_response(out.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=searches.csv"
    return resp

@app.route("/admin/api/stats")
@admin_required
def admin_api_stats():
    db = get_db()
    daily_s = db.execute("SELECT date(created_at) as d,COUNT(*) as c FROM searches WHERE created_at>=date('now','-14 days') GROUP BY d ORDER BY d").fetchall()
    daily_u = db.execute("SELECT date(created_at) as d,COUNT(*) as c FROM users WHERE created_at>=date('now','-14 days') GROUP BY d ORDER BY d").fetchall()
    daily_v = db.execute("SELECT date(created_at) as d,COUNT(*) as c FROM visitors WHERE created_at>=date('now','-14 days') GROUP BY d ORDER BY d").fetchall()
    return jsonify({
        "searches_daily": [{"date":r["d"],"count":r["c"]} for r in daily_s],
        "users_daily":    [{"date":r["d"],"count":r["c"]} for r in daily_u],
        "visitors_daily": [{"date":r["d"],"count":r["c"]} for r in daily_v],
    })

# ── SEO ──────────────────────────────────────────────────────────
@app.route("/sitemap.xml")
def sitemap():
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for p, prio in [("",".9"),("/login",".7"),("/register",".7")]:
        xml += f"  <url><loc>{SITE_URL}{p}</loc><changefreq>weekly</changefreq><priority>{prio}</priority></url>\n"
    xml += "</urlset>"
    return xml, 200, {"Content-Type": "application/xml"}

@app.route("/robots.txt")
def robots():
    return f"User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /api\nSitemap: {SITE_URL}/sitemap.xml", 200, {"Content-Type": "text/plain"}

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html", sitename=SITE_NAME, tiktok_url=TIKTOK_URL, author=AUTHOR), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("500.html", sitename=SITE_NAME, tiktok_url=TIKTOK_URL, author=AUTHOR), 500

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  ◈ {SITE_NAME} v2.0")
    print(f"  ◈ http://localhost:{port}")
    print(f"  ◈ Admin: {ADMIN_EMAIL} / {ADMIN_PASS}")
    print(f"  ◈ AI: {'✓ ACTIVE' if ANTHROPIC_KEY else '✗ No key (add ANTHROPIC_API_KEY)'}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
  if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
