.PHONY: build build-release run-release run-debug

clean:
	cargo clean

debug:
	cargo build

release:
	cargo build --release

run-debug: build
	sudo ./target/debug/pidshark

run-release: build-release
	sudo ./target/release/pidshark

all: clean debug run-debug
