# HyperProxy

**HyperProxy by HyperSoft** is an authenticated SOCKS5 TCP proxy designed for Telegram clients and other explicitly permitted TCP destinations.

> Version 1.0.0 · Docker · Python 3.12 · PostgreSQL

## Features

- SOCKS5 `CONNECT` with mandatory Username/Password authentication (RFC 1928 / RFC 1929).
- PostgreSQL-backed user accounts; passwords are stored as salted scrypt hashes.
- Bootstrap administrator account configured through environment variables.
- Default destination-port allowlist: `80,443,5222`.
- Rejects loopback, private, link-local, multicast, reserved, and other non-global destination IP addresses.
- Global and per-user concurrent connection limits.
- HTTP health endpoints on port `8080`.
- TCP SOCKS5 listener on port `4040`, compatible with Clever Cloud TCP Redirections.
- Minimal connection metadata only; destination hosts and payload contents are not stored.

HyperProxy is a **SOCKS5 proxy**, not an MTProto proxy. It supports TCP CONNECT only; UDP ASSOCIATE and BIND are intentionally disabled.

## Clever Cloud deployment

1. Create or keep the application with the **Docker** runtime and connect this repository's `main` branch.
2. Link a PostgreSQL add-on to the application. Clever Cloud should provide `POSTGRESQL_ADDON_URI` automatically.
3. Add these application environment variables:

   | Variable | Required | Example / default |
   |---|---:|---|
   | `PROXY_ADMIN_USERNAME` | Yes | `hypersoft-admin` |
   | `PROXY_ADMIN_PASSWORD` | Yes | A unique random secret, at least 16 characters |
   | `POSTGRESQL_ADDON_URI` | Yes* | Provided by the linked add-on |
   | `ALLOWED_PORTS` | No | `80,443,5222` |
   | `MAX_CONNECTIONS` | No | `200` |
   | `MAX_CONNECTIONS_PER_USER` | No | `20` |
   | `CONNECT_TIMEOUT_SECONDS` | No | `10` |
   | `AUTH_TIMEOUT_SECONDS` | No | `10` |

   `DATABASE_URL` may be used instead of `POSTGRESQL_ADDON_URI`.

4. Keep the Docker exposed HTTP port at `8080` and TCP port at `4040` (the Clever Cloud defaults). The container serves `/health` and `/ready` on HTTP port `8080` and listens for SOCKS5 on TCP port `4040`.
5. Keep the existing `cleverapps.io` TCP redirection. Your public endpoint is the application's `cleverapps.io` hostname and the public port assigned by Clever Cloud (currently shown in your console as `18067`). The public port forwards to container port `4040`.
6. Deploy the latest commit. Check `https://YOUR-APP.cleverapps.io/health` for the HTTP health response.

*Do not paste database credentials or proxy passwords into source files, GitHub issues, or chat messages. Set them only in Clever Cloud environment variables.

## Connect from Telegram

In Telegram, open **Settings → Data and Storage → Proxy Settings → Add Proxy → SOCKS5** and enter:

- **Server:** your app's `cleverapps.io` hostname
- **Port:** the public TCP redirection port shown by Clever Cloud
- **Username:** `PROXY_ADMIN_USERNAME`
- **Password:** `PROXY_ADMIN_PASSWORD`

Do not enter the internal port `4040` in Telegram when connecting through Clever Cloud's public load balancer.

## Local development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Set POSTGRESQL_ADDON_URI and a strong PROXY_ADMIN_PASSWORD in .env
set -a && . ./.env && set +a
python -m hyperproxy
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

Build the container:

```bash
docker build -t hypersoft/hyperproxy:1.0.0 .
```

## Security notes

- Never run this service without a strong bootstrap username and password.
- Do not remove the destination IP checks or connection limits for a public deployment.
- Only destination ports listed in `ALLOWED_PORTS` are accepted. Add ports only when you understand why clients need them.
- The proxy does not decrypt TLS traffic. It forwards TCP bytes to the requested public destination.
- The load balancer may hide the original client IP from the application; per-user authentication and connection limits are therefore used instead of trusting source IPs.
- The bootstrap account's password is synchronized from the nvironment on startup. Changing the environment value and redeploying rotates that account's password.

## Health endpoints

- `GET /` or `GET /health` — process liveness.
- `GET /ready` — PostgreSQL readiness.

## License

No license has been selected for this repository yet.
