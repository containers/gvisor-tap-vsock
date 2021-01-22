FROM registry.access.redhat.com/ubi8/ubi AS build
WORKDIR /go/src/app
RUN yum -y install golang make
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN make

FROM scratch
COPY --from=build /go/src/app/bin/vm .
ENTRYPOINT ["/vm"]
