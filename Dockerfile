FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
ARG VERSION=1.0.0
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /tvlift .

FROM scratch
COPY --from=build /tvlift /tvlift
USER 65534:65534
EXPOSE 8088
HEALTHCHECK --interval=60s --timeout=5s CMD ["/tvlift", "healthcheck"]
ENTRYPOINT ["/tvlift"]
CMD ["serve"]
