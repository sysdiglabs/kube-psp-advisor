.PHONY: all

all: build test

test:
	@echo "+ $@"
	./scripts/test
build:
	@echo "+ $@"
	./scripts/build
