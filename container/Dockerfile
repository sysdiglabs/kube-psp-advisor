FROM golang:1.11.5-alpine3.8
RUN apk add --no-cache git curl
WORKDIR $GOPATH/src/kube-psp-advisor
COPY . .
# aws-iam-authenticator is optional, please install necessary k8s cloud authenticator accordingly
RUN curl -o aws-iam-authenticator https://amazon-eks.s3-us-west-2.amazonaws.com/1.11.5/2018-12-06/bin/linux/amd64/aws-iam-authenticator
RUN chmod u+x aws-iam-authenticator
RUN mv aws-iam-authenticator /usr/local/bin
RUN go get -d -v ./...
RUN env GOOS=$(uname -s | tr '[:upper:]' '[:lower:]') GOARCH=amd64 CGO_ENABLED=0 go build -a 
ENV PATH /go/src/kube-psp-advisor:$PATH
RUN apk del curl

ENTRYPOINT ["kube-psp-advisor"]
