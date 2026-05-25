FROM alpine:3.20

RUN apk add --no-cache fuse3

COPY spiffefs /usr/bin/spiffefs

ENTRYPOINT ["/usr/bin/spiffefs"]
