FROM ghcr.io/ahobsonsayers/androotu:latest

ARG FRIDA_VERSION=17.17.0

RUN apt-get update && apt-get install -y --no-install-recommends xz-utils jq python3-cryptography && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/tools && \
    curl -fsSL -o /tmp/frida.xz \
      "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-x86_64.xz" && \
    xz -dc /tmp/frida.xz > /opt/tools/frida-server && \
    rm -f /tmp/frida.xz && \
    chmod +x /opt/tools/frida-server

COPY scripts /opt/scripts/

RUN chmod +x /opt/scripts/*.sh /opt/scripts/*.py
