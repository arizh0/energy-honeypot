#!/bin/sh
# Generate a self-signed TLS cert at container startup (not at build time).
# Generating at runtime keeps the private key out of image layers, which
# prevents Trivy / image-scanning tools from flagging it as a leaked secret.
set -e

if [ ! -f /etc/nginx/key.pem ] || [ ! -f /etc/nginx/cert.pem ]; then
    rm -f /etc/nginx/key.pem /etc/nginx/cert.pem
    openssl req -x509 -newkey rsa:2048 \
        -keyout /etc/nginx/key.pem \
        -out    /etc/nginx/cert.pem \
        -days 3650 -nodes \
        -subj "/C=GB/ST=England/L=London/O=HelioControl Ltd/CN=helio-ctrl-01"
    chmod 600 /etc/nginx/key.pem
fi

exec "$@"
