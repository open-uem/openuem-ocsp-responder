FROM golang:latest AS build
COPY . ./
RUN go build -o "/bin/openuem-ocsp-responder" .

FROM debian:latest
EXPOSE 8000
COPY --from=build /bin/openuem-ocsp-responder /bin/openuem-ocsp-responder
ENTRYPOINT ["/bin/openuem-ocsp-responder"]