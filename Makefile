.PHONY: clean test

clean:
	find . -name '*.py[co]' -delete

test:
	cargo build --release
	mv target/release/libpk2.so target/release/pk2.so
	python3 script.py 