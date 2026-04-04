# LiquidationOsint 🔍

**Профессиональный OSINT Framework** — поиск по телефону, email, IP, нику, ФИО, домену.

## Функции
- 📞 Phone lookup (оператор, страна, Gravatar, ссылки)
- ✉ Email lookup (Gravatar, MX, HIBP, LeakCheck)
- 🌐 IP + Shodan (GeoIP, CVE, порты, VPN детект)
- 👤 Sherlock 62+ платформы
- 🔒 Domain + WHOIS + DNS + Certificate Transparency
- 🔍 Google Dorks под каждый тип
- 📡 Проверка 15 соцсетей
- 👥 Регистрация / вход пользователей
- ⚙ Полная Admin панель (логи, юзеры, поиски, визиты)
- 🗺 SEO (sitemap.xml, robots.txt, мета-теги)

---

## Локальный запуск

```bash
pip install -r requirements.txt
python app.py
# → http://localhost:5000
```

Админ: email из ADMIN_EMAIL / пароль из ADMIN_PASS (по умолчанию admin@liquidationosint.com / admin1234)

---

## Деплой на Railway (бесплатно)

### Шаг 1 — GitHub
1. Зайди на https://github.com и создай аккаунт (если нет)
2. Нажми "+" → "New repository"
3. Назови `liquidation-osint`, сделай **Private**, создай
4. Загрузи все файлы этой папки в репозиторий

### Шаг 2 — Railway
1. Зайди на https://railway.app
2. Войди через GitHub (кнопка "Login with GitHub")
3. Нажми **"New Project"** → **"Deploy from GitHub repo"**
4. Выбери свой репозиторий `liquidation-osint`
5. Railway автоматически найдёт `Procfile` и задеплоит

### Шаг 3 — Переменные окружения (ВАЖНО!)
В Railway → твой проект → вкладка **Variables** добавь:

| Переменная | Значение | Описание |
|---|---|---|
| `SECRET_KEY` | `любой_длинный_случайный_текст` | Ключ сессий |
| `ADMIN_EMAIL` | `твой@email.com` | Логин админа |
| `ADMIN_PASS` | `твой_сильный_пароль` | Пароль админа |
| `SITE_URL` | `https://твой-проект.up.railway.app` | URL сайта (для sitemap) |

### Шаг 4 — Получить домен
Railway → твой проект → **Settings** → **Domains** → **Generate Domain**
Получишь `https://liquidation-osint.up.railway.app` или похожее.

---

## SEO — попасть в Google

После деплоя:
1. Зайди на https://search.google.com/search-console
2. Добавь свой домен Railway
3. Подтверди через HTML тег (добавь в base.html в `<head>`)
4. Отправь sitemap: `https://твой-сайт.up.railway.app/sitemap.xml`
5. Google проиндексирует за 1-4 недели

---

## Структура проекта
```
project/
├── app.py              # Основной Flask файл
├── requirements.txt    # Зависимости Python
├── Procfile            # Команда запуска для Railway
├── railway.toml        # Конфиг Railway
├── .gitignore
└── templates/
    ├── base.html       # Базовый шаблон (nav, footer)
    ├── index.html      # Главная страница / поиск
    ├── auth.html       # Вход / регистрация
    ├── profile.html    # Профиль пользователя
    └── admin.html      # Панель администратора
```

---

## Admin панель

URL: `/admin` (только для аккаунта с ролью admin)

Возможности:
- 📊 Графики поисков и регистраций за 14 дней
- 👥 Список всех пользователей (бан/разбан/удаление)
- 🔍 Лог всех поисков (кто/что/когда/IP)
- 📡 Все визиты (IP, страна, город, ISP, браузер)
- 📈 Топ запросов и топ IP
- ⚙ Настройки сайта (обязательный логин, режим обслуживания)
