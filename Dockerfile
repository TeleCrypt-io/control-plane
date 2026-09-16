# Exact version tag by operator policy; upgrade deliberately after validation.
FROM golang:1.26.4-alpine AS controlplane-build

# Janitor's SMTP STARTTLS client verifies the mail server certificate.
RUN apk add --no-cache ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/registration ./cmd/registration
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/janitor ./cmd/janitor
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/plan ./cmd/plan

# Runtime: scratch — no shell, no package manager. The public control-plane image ships registration,
# janitor, and Plan. The private Cashier image owns all billing service code and Dodo access.
# Registration reaches MAS through its browser-visible HTTPS URL and Janitor's SMTP digest also uses
# verified TLS, so the shared runtime bundle must contain the CA trust store.
#
# The tier controller is intentionally absent from this image. GitHub Actions releases it only as a
# wheel; the standalone telecrypt-synapse builder downloads that exact release asset and verifies
# its checksum after that repository updates its pinned manifest.
#
# CMD defaults to the Registration component. It is a default, rather than an ENTRYPOINT, because this
# one image contains three separately deployed components; Janitor and Plan replace CMD.
FROM scratch AS controlplane
LABEL org.opencontainers.image.source="https://github.com/TeleCrypt-io/control-plane"
LABEL org.opencontainers.image.licenses="BUSL-1.1"
LABEL org.opencontainers.image.title="TeleCrypt Controlplane"
LABEL org.opencontainers.image.description="TeleCrypt Registration, Janitor, and Plan services"
LABEL org.opencontainers.image.vendor="TeleCrypt.io"
LABEL io.telecrypt.config-contract="1"
COPY --from=controlplane-build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY LICENSE /LICENSE
COPY NOTICE /NOTICE
COPY --from=controlplane-build /out/registration /registration
COPY --from=controlplane-build /out/janitor /janitor
COPY --from=controlplane-build /out/plan /plan
USER 991:991
CMD ["/registration"]
