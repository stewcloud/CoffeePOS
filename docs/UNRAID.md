# Unraid test deployment (v0.1.0)

CoffeePOS currently queues print jobs but does not send them to printers. Keep this test installation LAN-only; do not publish via Cloudflare yet.

## Install

1. Open an Unraid terminal.
2. Run:
   ```bash
   mkdir -p /mnt/user/appdata/coffeepos
   cd /mnt/user/appdata/coffeepos
   git clone https://github.com/stewcloud/CoffeePOS.git source
   cd source
   cp .env.example .env
   ```
3. Edit `.env`: replace `SECRET_KEY` with a long random string and `ADMIN_PIN` with a unique four-digit PIN. Do not commit `.env`.
4. Run `docker compose up -d --build`.
5. Check `docker compose ps` and `docker compose logs --tail=100`.
6. Test `http://NAS-IP:8541/api/health` and `http://NAS-IP:8541/`.

The app uses its own `coffeepos` container and `./data` volume. BarPrep and brother-ql-web are not modified.

## Update

```bash
cd /mnt/user/appdata/coffeepos/source
git pull --ff-only
docker compose up -d --build
```

## Troubleshooting

- Check that host port 8541 is unused before starting.
- The initial Admin user is created only when the database is empty.
- For the test release, print jobs remain pending intentionally.
- Authentication is not hardened for Internet exposure; use only on a trusted LAN.

## Rollback

```bash
cd /mnt/user/appdata/coffeepos/source
docker compose down
```

Persistent database files remain under `./data`.
