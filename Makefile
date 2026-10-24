# One command gates everything: `make check`.
# Tip on a shared machine: export CARGO_TARGET_DIR / CARGO_BUILD_JOBS before running.

CARGO ?= cargo
COVERAGE_MIN ?= 80

.PHONY: check fmt-check lint doc test coverage vectors-verify vectors-fetch demo bench bench-table ct clean

## check: format-check + clippy (zero warnings) + rustdoc + doctests + all tests under coverage (>= COVERAGE_MIN% lines) + vector checksums
check: fmt-check lint doc vectors-verify coverage
	@echo "make check: OK"

fmt-check:
	$(CARGO) fmt --all -- --check

lint:
	$(CARGO) clippy --locked --all-targets -- -D warnings

doc:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --locked --no-deps
	$(CARGO) test --locked --doc

test:
	$(CARGO) test --locked

## coverage: runs the unit, integration, property and CLI tests with llvm-cov instrumentation
coverage:
	@command -v cargo-llvm-cov >/dev/null 2>&1 || { echo "cargo-llvm-cov is required: cargo install cargo-llvm-cov --locked"; exit 1; }
	$(CARGO) llvm-cov --locked --all-targets --ignore-filename-regex 'benches/' --fail-under-lines $(COVERAGE_MIN) --summary-only

vectors-verify:
	scripts/fetch-vectors.sh --verify-only

## vectors-fetch: re-download the pinned vectors from upstream and verify them (needs network)
vectors-fetch:
	scripts/fetch-vectors.sh

demo:
	$(CARGO) run --locked --release --quiet -- demo

bench:
	$(CARGO) bench --locked --bench kem

bench-table:
	$(CARGO) run --locked --release --quiet -- bench --iters 2000

ct:
	$(CARGO) run --locked --release --quiet -- ct-test --samples 100000

clean:
	$(CARGO) clean
