FROM registry.access.redhat.com/ubi8/go-toolset:1.14.12 AS build
WORKDIR $APP_ROOT/src
COPY . .
RUN make

FROM scratch
COPY --from=build /opt/app-root/src/bin/vm .
ENTRYPOINT ["/vm"]
