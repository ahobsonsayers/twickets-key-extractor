# Extends androotu: rooted A16 emulator that marks Play-installed apps as legit.
FROM ghcr.io/ahobsonsayers/androotu:latest

# Must match the frida client used at runtime.
ARG FRIDA_VERSION=17.17.0

# xz-utils: base lacks `xz` (frida unpack); jq: used to parse keys.
RUN apt-get update && apt-get install -y --no-install-recommends xz-utils jq && rm -rf /var/lib/apt/lists/*

# Fetch frida-server at build time so the ~106MB binary isn't committed.
RUN mkdir -p /opt/tools && \
    curl -fsSL -o /tmp/frida.xz \
      "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-x86_64.xz" && \
    xz -dc /tmp/frida.xz > /opt/tools/frida-server && \
    rm -f /tmp/frida.xz && \
    chmod +x /opt/tools/frida-server

# COPY last: scripts change often, so prior (static) layers keep their cache.
COPY scripts /opt/scripts/

RUN chmod +x /opt/scripts/*.sh
