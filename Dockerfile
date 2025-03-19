FROM golang:1.24.1 AS build
COPY . ./
RUN go build -o "/bin/openuem-ocsp-responder" .

FROM debian:latest
EXPOSE 8000
COPY --from=build /bin/openuem-ocsp-responder /bin/openuem-ocsp-responder
WORKDIR /tmp
ENTRYPOINT ["/bin/openuem-ocsp-responder"]