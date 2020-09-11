FROM golang:1.14 AS build
WORKDIR /go/src/app
COPY . .
RUN make

FROM centos
COPY --from=build /go/src/app/bin/vm .
ENTRYPOINT ["/vm", "-logtostderr", "-retry", "600"]