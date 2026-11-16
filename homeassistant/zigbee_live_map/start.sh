#!/command/with-contenv sh
# Starts zigbee-live-map from the options the Supervisor wrote to /data/options.json.
#
# Options are read with jq, not Bashio: Bashio asks the Supervisor API, which does not exist when the
# image is run by homeassistant/try-locally.sh (https://contributors.home-assistant.io/apps/guides/options/,
# "In any other language, read /data/options.json as JSON").
# with-contenv gives this script the container environment (https://contributors.home-assistant.io/apps/guides/s6-overlay/).
set -eu
set -f   # an option value is never a glob

OPTIONS_FILE=/data/options.json
INGRESS_PORT=8099   # = ingress_port in config.yaml (a test checks it)
DATA_DIR=/data      # the app's private persistent directory (https://contributors.home-assistant.io/apps/reference/environment/)

opt() { jq -r "$1" "$OPTIONS_FILE"; }

# --ingress trusts only the Supervisor (172.30.32.2) and needs no login; 0.0.0.0 so that it can reach us.
set -- zigbee-live-map --host 0.0.0.0 --port "$INGRESS_PORT" --ingress --data-dir "$DATA_DIR"

if [ "$(opt '.demo // false')" = "true" ]; then
    set -- "$@" --demo
else
    set -- "$@" --channel "$(opt '.channel // 11')"
fi

# The password and the allowed hosts only matter for a published port. The password goes in the environment,
# never on the command line. Host names are only checked where people sign in, and the tool refuses to start with
# names and no password: so without a password they are left out, with a line in the log saying so.
password="$(opt '.password // empty')"
hosts="$(opt '.allowed_hosts[]? | select(length > 0) | gsub("\n"; "\\n")')"
if [ -n "$password" ]; then
    export ZLM_PASSWORD="$password"
    # One line per list element, each becoming exactly one argument (never split on spaces). An empty element is skipped. A line
    # break cannot be told apart from the end of an element, so jq writes it as \n: the tool then refuses that "host name" by name.
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        set -- "$@" --allowed-host "$name"
    done <<EOF
$hosts
EOF
elif [ -n "$hosts" ]; then
    echo "zigbee-live-map: allowed_hosts is ignored because no password is set (a published port needs both)" >&2
fi

exec "$@"
