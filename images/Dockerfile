FROM registry.access.redhat.com/ubi8/go-toolset:1.16.12 AS build
WORKDIR $APP_ROOT/src
COPY . .
RUN make

FROM busybox
COPY images/udhcpc.sh /usr/share/udhcpc/default.script
RUN chmod +x /usr/share/udhcpc/default.script
COPY --from=build /opt/app-root/src/bin/vm .
ENTRYPOINT ["/vm"]
