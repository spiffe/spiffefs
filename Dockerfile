FROM alpine:3.20

RUN apk add --no-cache fuse3

ARG TARGETARCH
COPY dist/spiffefs_linux_${TARGETARCH}*/spiffefs /usr/bin/spiffefs

ENTRYPOINT ["/usr/bin/spiffefs"]
