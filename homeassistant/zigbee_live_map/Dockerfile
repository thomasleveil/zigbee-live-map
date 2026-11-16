# Pinned base image, multi-arch (amd64 and aarch64), Alpine with Python, S6 overlay v3, bash, jq, curl:
# https://contributors.home-assistant.io/apps/guides/dockerfile/ ("Pin a version ... instead of latest").
# A plain FROM: BUILD_FROM is no longer passed since Supervisor 2026.04.0 (same page).
FROM ghcr.io/home-assistant/base-python:3.14-alpine3.24

# libusb for pyusb (the dongle is a raw USB device, not a serial port). The package name is not in the
# Home Assistant docs; it is Alpine's own.
RUN apk add --no-cache libusb

# The tool arrives as a wheel built into this folder: the Supervisor builds with this folder as the build
# context, so the source in ../../src cannot be copied. See DOCS.md and homeassistant/try-locally.sh.
# --only-binary: no compiler is installed, so every dependency must come as a wheel.
COPY zigbee_live_map-*.whl /tmp/wheel/
RUN pip install --no-cache-dir --only-binary=:all: /tmp/wheel/*.whl && rm -rf /tmp/wheel

COPY start.sh /usr/local/bin/start.sh

# The base image's ENTRYPOINT ([/init], S6 overlay) is kept; CMD is "one program, and the app stops when it
# stops" (https://contributors.home-assistant.io/apps/guides/s6-overlay/, "Three ways to start your app").
CMD ["/usr/local/bin/start.sh"]
