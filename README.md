# HyperProxy

**HyperProxy by HyperSoft** provides authenticated SOCKS5 and optional Telegram MTProto proxy services behind one Clever Cloud TCP redirection.

> Version 1.1.0 · Docker · Python 3.12 · PostgreSQL · Telegram MTProxy

## Features

- SOCKS5 CONNECT with mandatory Username/Password authentication (RFC 1928 / RFC 1929).
- Optional official Telegram MTProxy with a stable 32-character hexadecimal secret.
- A small TCP protocol router dispatches SOCKS5 and MTProto over the same public TCP port.
- Optional Telegram promotion tag from @MTProxyBot to promote a public channel.
- PostgreSQL-backed SOCKS5 user accounts; passwords are stored as salted scrypt hashes.
- Private bootstrap administrator account configured through environment variables; administrator credentials are never accepted by the public SOCKS5 listener.
- Default SOCKS5 destination-port allowlist: 80,443,5222.
- SOCKS5 destination IPs must also belong to Telegram's published server CIDRs (`https://core.telegram.org/resources/cidr.txt`); other public IPs are rejected.
- Rejects loopback, private, link-local, multicast, reserved, and other non-global SOCKS5 destination IP addresses.
- Global and per-user concurrent SOCKS5 connection limits.
- HTTP health endpoints on port 8080.
- Minimal SOCKS5 connection metadata only; destination hosts and payload contents are not stored.

SOCKS5 and MTProto are separate protocols. SOCKS5 uses the administrator username/password; MTProto uses its own secret. The SOCKS5 destination policy does not apply to MTProto, which only forwards Telegram traffic.

## Clever Cloud deployment

1. Keep the application on the **Docker** runtime and connect this repository's main branch.
2. Keep the linked PostgreSQL add-on. Clever Cloud should provide POSTGRESQL_ADDON_URI automatically.
3. Keep the existing application environment variables:

   | Variable | Required | Example / default |
   |---|---:|---|
   | PROXY_ADMIN_USERNAME | Yes | hypersoft-admin |
   | PROXY_ADMIN_PASSWORD | Yes | Private administrator secret; never publish it |\n   | PROXY_PUBLIC_USERNAME | Recommended | Public SOCKS5 username, different from admin |\n   | PROXY_PUBLIC_PASSWORD | Recommended | Public SOCKS5 password, 16–128 characters |
   | POSTGRESQL_ADDON_URI | Yes* | Provided by the linked add-on |
   | ALLOWED_PORTS | No | 80,443,5222 |
   | TELEGRAM_ALLOWED_CIDRS | No | Built-in official Telegram CIDRs; leave empty for defaults |
   | MAX_CONNECTIONS | No | 200 |
   | MAX_CONNECTIONS_PER_USER | No | 20 |
   | DB_POOL_MIN_SIZE | No | 1 |
   | DB_POOL_MAX_SIZE | No | 3 |
   | DB_POOL_IDLE_SECONDS | No | 60 |

   DATABASE_URL may be used instead of POSTGRESQL_ADDON_URI.

   PostgreSQL pool settings are separate from SOCKS5 client limits. The default pool opens 1 connection and grows only when needed, up to 3; idle connections are retired after 60 seconds. If PostgreSQL briefly rejects connections because its role limit is reached, startup retries pool creation twice with short backoff delays. The pool size can be lowered further with DB_POOL_MAX_SIZE=1 if the database plan has a very small per-role connection limit.

   Configure PROXY_PUBLIC_USERNAME and PROXY_PUBLIC_PASSWORD to create the separate public SOCKS5-only account. If these are unset, no public user account is enabled and the administrator account cannot connect through SOCKS5. Keep the administrator credentials private and different from the public credentials.\n\n4. Keep the existing Clever Cloud TCP redirection pointing to internal port 4040. **Do not create another redirection or change the current public port.** The router on 4040 dispatches traffic to the SOCKS5 backend on 4041 or the MTProto backend on 4042.
5. Keep the HTTP health server on 8080. Check https://YOUR-APP.cleverapps.io/health and /ready.
6. MTProto is optional. If MTPROTO_SECRET is empty, the public TCP listener continues to route traffic to SOCKS5 only.

*Do not paste database credentials, SOCKS5 passwords, MTProto secrets, or proxy tags into source files, GitHub issues, or chat messages. Set them only in Clever Cloud environment variables.

## Enable MTProto

1. Generate a 16-byte secret on your device or in Termux:

   ~~~bash
   openssl rand -hex 16
   ~~~

   The output must be exactly 32 hexadecimal characters. Keep it stable across redeployments.
2. Add the generated value to the Clever Cloud environment variable MTPROTO_SECRET. Leave MTPROTO_PROXY_TAG empty for the first deployment.
3. Deploy and wait for the log line confirming that MTProto is listening on internal port 4042.
4. Use the application's existing public Clever Cloud hostname and TCP redirection port to register the proxy with Telegram's official @MTProxyBot:
   - Send /newproxy.
   - Send YOUR-APP.cleverapps.io:YOUR_EXISTING_PUBLIC_TCP_PORT.
   - Send the 32-character MTPROTO_SECRET.
   - Save the 32-character proxy tag returned by the bot.
5. Add the returned tag as MTPROTO_PROXY_TAG in Clever Cloud and redeploy. HyperProxy passes it to the official MTProxy process using the -P option.
6. In @MTProxyBot, open /myproxies, select the registered proxy, choose **Set promotion**, and submit the public channel link:

   https://t.me/HyperSoft26

   Telegram controls when the promotion appears to connected users. It is not an automatic channel subscription.

## Connect from Telegram

### SOCKS5

Open **Settings → Data and Storage → Proxy Settings → Add Proxy → SOCKS5**:

- **Server:** your app's cleverapps.io hostname
- **Port:** the existing public TCP redirection port
- **Username:** PROXY_ADMIN_USERNAME
- **Password:** PROXY_ADMIN_PASSWORD

### MTProto

After MTProto is enabled, share a link in this format:

~~~text
https://t.me/proxy?server=YOUR-APP.cleverapps.io&port=YOUR_EXISTING_PUBLIC_TCP_PORT&secret=YOUR_MTPROTO_SECRET
~~~

MTProto does not use the SOCKS5 username or password. It uses the separate MTPROTO_SECRET.

## Local development

~~~bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Set POSTGRESQL_ADDON_URI and a strong PROXY_ADMIN_PASSWORD in .env
set -a && . ./.env && set +a
python -m hyperproxy
~~~

Run tests:

~~~bash
python -m unittest discover -s tests -v
~~~

Build the container:

~~~bash
docker build -t hypersoft/hyperproxy:1.1.0 .
~~~

## Security notes

- Never publish PROXY_ADMIN_USERNAME or PROXY_ADMIN_PASSWORD. SOCKS5 rejects accounts with the admin role; only the separate role=user public account can authenticate.
- Do not remove the SOCKS5 destination IP checks or connection limits for a public deployment.
- SOCKS5 can connect only to IP addresses inside Telegram's published CIDR ranges and to destination ports listed in ALLOWED_PORTS. Other public IPs, private networks, localhost, metadata endpoints, and non-Telegram destinations are rejected.
- Telegram may change its published CIDRs. Review `https://core.telegram.org/resources/cidr.txt` and update the built-in list when Telegram changes it. Do not broaden the list to `0.0.0.0/0` or `::/0`.
- SOCKS5 cannot reliably identify which client application initiated a connection. A user may technically use another SOCKS5-capable app, but the proxy will still only permit connections to the allowlisted Telegram networks and ports.
- MTProto is a Telegram-specific proxy, not a general-purpose VPN.
- Keep the MTProto secret and promotion tag in Clever Cloud environment variables. Share the MTProto secret only with intended proxy users.
- The proxy does not decrypt Telegram message contents. The operator can still observe connection metadata such as client IP addresses and connection times.
- The load balancer may hide the original client IP from the application; per-user SOCKS5 authentication and connection limits are therefore used instead of trusting source IPs.
- The private administrator password and public SOCKS5 password are stored as separate salted hashes. Changing either environment variable and redeploying synchronizes that account's password.

## Health endpoints

- GET / or /health — process liveness.
- GET /ready — PostgreSQL readiness.

## License

No license has been selected for HyperProxy's own Python code. See THIRD_PARTY_NOTICES.md for the included Telegram MTProxy component.
