FROM anchore/grype:latest AS grype

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=grype /grype /usr/local/bin/grype
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/vuln-check /usr/local/bin/vuln-check
ENV GRYPE_DB_CACHE_DIR=/cache/grype
VOLUME ["/cache"]
WORKDIR /work
ENTRYPOINT ["vuln-check"]
CMD ["scan", "--no-osv", "."]
