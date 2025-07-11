FROM golang:1.24.4 AS build
COPY . ./
RUN go build -o "/bin/openuem-ocsp-responder" .

FROM debian:latest
EXPOSE 8000
COPY --from=build /bin/openuem-ocsp-responder /bin/openuem-ocsp-responder
WORKDIR /tmp
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1
ENTRYPOINT ["/bin/openuem-ocsp-responder"]