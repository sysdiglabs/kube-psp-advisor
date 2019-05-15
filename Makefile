.PHONY: all

all: build test

test:
	@echo "+ $@"
	./scripts/test
example:
	@echo "+ $@"
	./scripts/example
build:
	@echo "+ $@"
	./scripts/build
