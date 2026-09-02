FROM scratch
LABEL org.opencontainers.image.source=https://github.com/chisaato/openbao-plugin-secrets-acme
COPY bin/openbao-plugin-secrets-acme /openbao-plugin-secrets-acme
ENTRYPOINT ["/openbao-plugin-secrets-acme"]
