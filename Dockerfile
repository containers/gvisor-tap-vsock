FROM golang:1.14 AS build
WORKDIR /go/src/app
COPY . .
RUN make

FROM centos
RUN yum install -y net-tools iproute
COPY --from=build /go/src/app/bin/vm .
CMD ["/vm", "-logtostderr"]
