FROM registry.access.redhat.com/ubi9/go-toolset:latest AS build
WORKDIR $APP_ROOT/src
COPY . .
RUN make

FROM busybox
COPY images/udhcpc.sh /usr/share/udhcpc/default.script
COPY --from=build /opt/app-root/src/bin/gvforwarder .
ENTRYPOINT ["/gvforwarder"]
