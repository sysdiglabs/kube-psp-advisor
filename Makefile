.PHONY: all

all: build test
IMG="sysdig/kube-psp-advisor"
VERSION=$(shell cat version)

test:
	@echo "+ $@"
	./scripts/test
example:
	@echo "+ $@"
	./scripts/example
build:
	@echo "+ $@"
	./scripts/build
build-release:
	@echo "+ $@"
	./scripts/build-release
build-image:
	@echo "+ $@"
	docker build -f container/Dockerfile -t ${IMG}:${VERSION} .
push-image:
	@echo "+ $@"
	docker push ${IMG}:${VERSION}
	docker tag ${IMG}:${VERSION} ${IMG}:latest
	docker push ${IMG}:latest
