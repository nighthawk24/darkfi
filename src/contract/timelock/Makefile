.POSIX:

# Cargo binary
CARGO = cargo +nightly

# zkas compiler binary
ZKAS = ../../../zkas

# zkas circuits
PROOFS_SRC = $(shell find proof -type f -name '*.zk')
PROOFS_BIN = $(PROOFS_SRC:=.bin)

# wasm source files
WASM_SRC = \
	$(shell find src -type f) \
	$(shell find ../../sdk -type f -name '*.rs') \
	$(shell find ../../serial -type f -name '*.rs')

# wasm contract binary
WASM_BIN = timelock_contract.wasm

all: $(WASM_BIN)

$(WASM_BIN): $(WASM_SRC) $(PROOFS_BIN)
	$(CARGO) build --release --package darkfi-timelock-contract --target wasm32-unknown-unknown
	cp -f ../../../target/wasm32-unknown-unknown/release/darkfi_timelock_contract.wasm $@

$(PROOFS_BIN): $(ZKAS) $(PROOFS_SRC)
	$(ZKAS) $(basename $@) -o $@

test-integration: all
	$(CARGO) test --release --features=no-entrypoint,client \
		--package darkfi-timelock-contract \
		--test integration $(ARGS)

test: test-integration

clean:
	rm -f $(PROOFS_BIN) $(WASM_BIN)

.PHONY: all test test-integration clean
