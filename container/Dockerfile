FROM golang:1.12.9-alpine3.10 AS builder
RUN apk add --no-cache build-base git
WORKDIR $GOPATH/src/kube-psp-advisor
COPY . $GOPATH/src/kube-psp-advisor
ENV GO111MODULE=on
RUN go get golang.org/x/tools/cmd/goimports
RUN make build

FROM alpine
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
COPY --from=builder /go/src/kube-psp-advisor/kube-psp-advisor /kube-psp-advisor

ENTRYPOINT ["kube-psp-advisor"]
CMD ["inspect"]
