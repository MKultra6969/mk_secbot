# mk-secbot

Telegram bot on Python (`aiogram`) for CrowdSec:
- ban IP (`/ban`)
- unban IP (`/unban`)
- forward CrowdSec alerts to a dedicated private chat
- strict admin allowlist by Telegram `user_id` (all others are ignored)

## 1. Requirements

- Docker + Docker Compose plugin
- CrowdSec Local API reachable from bot host (example: `http://192.168.1.27:8080`)
- Telegram bot token from `@BotFather`

## 2. CrowdSec machine credentials

Create machine credentials on the CrowdSec host:

```bash
cscli machines add mk-secbot
```

This returns:
- `machine_id`
- `password`

Use these credentials in `.env` (`CROWDSEC_MACHINE_ID`, `CROWDSEC_MACHINE_PASSWORD`).

## 3. Setup `.env`

```bash
copy .env.example .env
```

Linux/macOS:

```bash
cp .env.example .env
```

Edit `.env` and fill required values:
- `TELEGRAM_BOT_TOKEN`
- `ADMIN_USER_IDS` (comma-separated user IDs, e.g. `111,222`)
- `ALERT_CHAT_ID` (ID of private alert chat)
- `CROWDSEC_MACHINE_ID`
- `CROWDSEC_MACHINE_PASSWORD`

Main connection parameter for your case:
- `CROWDSEC_BASE_URL=http://192.168.1.27:18080`
- `CROWDSEC_USER_AGENT=crowdsec/v1.7.6-linux`

## 4. Run with Docker Compose

Build and start:

```bash
docker compose up -d --build
```

Logs:

```bash
docker compose logs -f
```

Stop:

```bash
docker compose down
```

Restart after `.env`/code changes:

```bash
docker compose up -d --build
```

## 5. Bot commands

- `/status` - check CrowdSec API auth
- `/ban <ip> [duration] [reason]`
- `/unban <ip>`
- `/alerts [count]` - show recent alerts (1..15)
- `/help`

Examples:

```text
/ban 1.2.3.4
/ban 1.2.3.4 12h ssh brute force
/unban 1.2.3.4
```

## 6. Security notes

- Bot ignores any non-admin user without response.
- Keep `.env` private and never commit it.
- Restrict network access to CrowdSec API (firewall allowlist for bot host).

## 7. GitHub publish

```bash
git init
git add .
git commit -m "Initial CrowdSec Telegram bot"
git branch -M main
git remote add origin <your_repo_url>
git push -u origin main
```
