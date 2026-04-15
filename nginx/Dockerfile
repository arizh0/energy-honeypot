FROM nginx:1.27-alpine

# Upgrade all Alpine packages first so patched versions of libexpat, libpng,
# and libxml2 are present in the image (fixes Trivy HIGH/CRITICAL findings).
# openssl is needed at runtime by entrypoint.sh to generate the self-signed cert.
# hadolint ignore=DL3018
RUN apk upgrade --no-cache && \
    apk add --no-cache openssl

COPY nginx.conf    /etc/nginx/nginx.conf
COPY entrypoint.sh /entrypoint.sh
RUN  chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
