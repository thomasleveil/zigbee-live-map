#!/bin/sh
# Check the Home Assistant app end to end without Home Assistant.
#
#   homeassistant/try-locally.sh          build the wheel and the image, start the app and a proxy, print the URL
#   homeassistant/try-locally.sh down     remove everything this script created
#
# It reproduces what a real ingress request goes through, and nothing more:
#   - a Docker network with Home Assistant's internal subnet, 172.30.32.0/23;
#   - the app container on it, started like the Supervisor would (no --init, /data mounted, options in /data/options.json);
#   - a reverse proxy at exactly 172.30.32.2 (the Supervisor's address) that serves the app under a path prefix,
#     HTTP and WebSocket, adds X-Ingress-Path, and asks for no login;
#   - one port published on 127.0.0.1 of this computer.
# It does NOT run a Supervisor, does not check anyone's Home Assistant session, and passes no USB device. The app gets a dummy
# SUPERVISOR_TOKEN (see below), without which --ingress refuses to start.
#
# Settings (environment): ZLM_TRY_PORT  host port on 127.0.0.1 (default 8798)
#                         ZLM_TRY_DEMO  true (default): simulated network. false: the real mode with no dongle
#                                       attached, which is what writes device lists to the data directory.
# Everything it creates is named zlm-*. Needs docker and uv.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
APP_DIR="$HERE/zigbee_live_map"
WORK="$HERE/.try-locally"       # data directory, options file, proxy configuration: removed by "down"
IMAGE=zlm-zigbee-live-map:local
NET=zlm-net
SUBNET=172.30.32.0/23
GATEWAY=172.30.32.1
SUPERVISOR_IP=172.30.32.2       # where Home Assistant's ingress proxy connects from
APP_IP=172.30.33.10
APP=zlm-app
PROXY=zlm-proxy
PROXY_IMAGE=nginx:1.29-alpine   # only a stand-in for the Supervisor's proxy
PORT=${ZLM_TRY_PORT:-8798}
DEMO=${ZLM_TRY_DEMO:-true}
PREFIX=/api/hassio_ingress/local   # the shape of a real ingress path; the token part is made up
INGRESS_PORT=$(sed -n 's/^ingress_port: *//p' "$APP_DIR/config.yaml")

die() { echo "error: $*" >&2; exit 1; }

down() {
    docker rm -f "$PROXY" "$APP" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    if [ -d "$WORK" ]; then
        # the container wrote to the data directory as root: let it clean up what this user may not remove
        if docker image inspect "$IMAGE" >/dev/null 2>&1; then
            docker run --rm --entrypoint rm -v "$WORK:/work" "$IMAGE" -rf /work/data >/dev/null 2>&1 || true
        fi
        rm -rf "$WORK"
    fi
    docker image rm "$IMAGE" >/dev/null 2>&1 || true
    echo "removed: containers $APP and $PROXY, network $NET, image $IMAGE, $WORK"
}

case "${1:-up}" in
    down) down; exit 0 ;;
    up) ;;
    *) die "usage: $0 [up|down]" ;;
esac

command -v docker >/dev/null || die "docker is not installed"
command -v uv >/dev/null || die "uv is not installed (it builds the wheel)"
case "$DEMO" in true|false) ;; *) die "ZLM_TRY_DEMO must be true or false" ;; esac
[ -n "$INGRESS_PORT" ] || die "no ingress_port in $APP_DIR/config.yaml"

for name in "$APP" "$PROXY"; do
    ! docker container inspect "$name" >/dev/null 2>&1 || die "container $name exists: run $0 down first"
done
! docker network inspect "$NET" >/dev/null 2>&1 || die "network $NET exists: run $0 down first"

echo "== wheel"
rm -f "$APP_DIR"/*.whl
# Built elsewhere, then copied: uv writes a .gitignore that ignores everything into its output folder,
# which would hide the whole app folder from git.
WHEEL_DIR=$(mktemp -d)
(cd "$HERE/.." && uv build --wheel --out-dir "$WHEEL_DIR")
cp "$WHEEL_DIR"/zigbee_live_map-*.whl "$APP_DIR/"
rm -rf "$WHEEL_DIR"

echo "== image"
docker build -t "$IMAGE" "$APP_DIR"

echo "== network $NET ($SUBNET)"
docker network create --subnet "$SUBNET" --gateway "$GATEWAY" "$NET" >/dev/null

echo "== app ($APP at $APP_IP, demo=$DEMO)"
mkdir -p "$WORK/data"
printf '{"channel": 11, "demo": %s, "allowed_hosts": []}\n' "$DEMO" > "$WORK/data/options.json"
# SUPERVISOR_TOKEN is a dummy, on purpose: the app starts with --ingress only where Home Assistant started it, and it knows
# that by this variable, which the Supervisor sets in every app container. Here nothing checks its value, so any text will do.
docker run -d --name "$APP" --network "$NET" --ip "$APP_IP" -e SUPERVISOR_TOKEN=dummy-not-a-supervisor-token \
    -v "$WORK/data:/data" "$IMAGE" >/dev/null

echo "== proxy ($PROXY at $SUPERVISOR_IP, $PREFIX/ -> $APP:$INGRESS_PORT)"
# The app does not check Host on the ingress channel, by design (Home Assistant's proxy stands in front of it). This
# stand-in therefore answers only the names the published port is meant to be reached by, 127.0.0.1:$PORT and localhost:$PORT, and
# refuses any other Host, so that a web page you visit cannot use DNS rebinding to reach the app through this proxy.
cat > "$WORK/proxy.conf" <<EOF
map \$http_upgrade \$connection_upgrade { default upgrade; '' close; }
server {
    listen 80;
    if (\$http_host !~ "^(127\\.0\\.0\\.1|localhost):$PORT\$") { return 403; }
    location $PREFIX/ {
        proxy_pass http://$APP:$INGRESS_PORT/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Ingress-Path $PREFIX;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_buffering off;
        proxy_read_timeout 3600s;
    }
}
EOF
docker run -d --name "$PROXY" --network "$NET" --ip "$SUPERVISOR_IP" -p "127.0.0.1:$PORT:80" \
    -v "$WORK/proxy.conf:/etc/nginx/conf.d/default.conf:ro" "$PROXY_IMAGE" >/dev/null

URL="http://127.0.0.1:$PORT$PREFIX/"
echo "== waiting for $URL"
tries=0
until [ "$(curl -s -o /dev/null -w '%{http_code}' "$URL" || true)" = "200" ]; do
    tries=$((tries + 1))
    if [ "$tries" -ge 40 ]; then
        docker logs "$APP" 2>&1 | tail -20
        die "the page did not answer 200 in 40 s (logs above); clean up with: $0 down"
    fi
    sleep 1
done

cat <<EOF

Open:  $URL
Data:  $WORK/data   (mounted as /data in the app)
Logs:  docker logs -f $APP
Stop:  $0 down
EOF
