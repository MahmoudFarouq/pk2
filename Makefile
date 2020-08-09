.PHONY: clean build

clean:
	find . -name '*.py[co]' -delete

build:
	cargo build --release
	./build-wheels.sh