FROM debian:bookworm-slim AS mtproxy-build

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git build-essential libssl-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/TelegramMessenger/MTProxy.git /src/MTProxy
WORKDIR /src/MTProxy
RUN make -j"$(nproc)" \
    && test -x objs/bin/mtproto-proxy


FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 zlib1g \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --system hyperproxy \
    && useradd --system --gid hyperproxy --home-dir /app hyperproxy

COPY --from=mtproxy-build /src/MTProxy/objs/bin/mtproto-proxy /usr/local/bin/mtproto-proxy
COPY --from=mtproxy-build /src/MTProxy /usr/src/MTProxy
COPY --from=mtproxy-build /src/MTProxy/GPLv2 /usr/share/licenses/mtproxy/GPLv2
COPY --from=mtproxy-build /src/MTProxy/LGPLv2 /usr/share/licenses/mtproxy/LGPLv2

COPY hyperproxy ./hyperproxy

USER hyperproxy

# Only the TCP router and required HTTP health listener are application-facing.
# SOCKS5, MTProto, and MTProxy stats stay bound to loopback inside the container.
EXPOSE 4040 8080

CMD ["python", "-m", "hyperproxy"]
