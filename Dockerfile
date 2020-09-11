FROM golang:1.14 AS build
WORKDIR /go/src/app
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN make

FROM scratch
COPY --from=build /go/src/app/bin/vm .
ENTRYPOINT ["/vm", "-logtostderr", "-retry", "600"]