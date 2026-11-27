include tests/fixtures.mk

NIGHTLY_RUST_VERSION ?= nightly
TAPLO_CLI_VERSION ?= 0.9.3
# The OpenSSL binaries the golden files and the interop tests use.
OPENSSL_30 ?= openssl
OPENSSL_3 ?= openssl
OPENSSL_4 ?= openssl
OPENSSL ?= openssl
BALDSSL ?= target/debug/baldssl
FUZZ_TARGET ?= x509
FUZZ_SECONDS ?= 60
SHELL_SCRIPTS := $(wildcard scripts/*.sh)

.PHONY: help
help: ## Ask for help!
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; \
		{printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "OpenSSL binaries on this machine, for make interop OPENSSL=..."
	@echo "(now OPENSSL=$(OPENSSL)):"
	@scripts/find-openssl.sh

# --- Build -------------------------------------------------------------------

.PHONY: build
build: ## Build in debug mode
	cargo build --workspace

.PHONY: build-release
build-release: ## Build in release mode
	cargo build --workspace --release

.PHONY: check
check: ## Check for compilation errors
	cargo check --workspace --all-targets

.PHONY: build-wasm
build-wasm: ## Build the libraries (browser) and the CLI (WASI) for WebAssembly
	cargo build --target wasm32-unknown-unknown \
		-p baldssl-core -p baldssl-crypto -p baldssl-x509
	cargo build --release --target wasm32-wasip1 -p baldssl

.PHONY: test-wasm
test-wasm: build-wasm fixtures ## Run the library tests and the golden suite as WebAssembly (needs wasmtime)
	CARGO_TARGET_WASM32_WASIP1_RUNNER="wasmtime run --dir /" \
		cargo test --release --target wasm32-wasip1 \
		-p baldssl-core -p baldssl-crypto -p baldssl-x509
	BALDSSL_BIN=$(CURDIR)/scripts/wasmtime-baldssl.sh \
		cargo test -p baldssl --test golden --test commands

.PHONY: check-aeneas
check-aeneas: ## Check the Lean-extraction subset builds with --cfg aeneas
	RUSTFLAGS="--cfg aeneas" cargo check -p baldssl-core -p baldssl-crypto \
		--target-dir target/aeneas

.PHONY: doc
doc: ## Build the public API documentation, warnings as errors
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

.PHONY: doc-private
doc-private: ## Build the documentation of private items too, warnings as errors
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps \
		--document-private-items --target-dir target/doc-private

# --- Formatting and lints ----------------------------------------------------

.PHONY: format
format: format-md ## Format Rust (nightly rustfmt), TOML (taplo), markdown
	cargo +$(NIGHTLY_RUST_VERSION) fmt --all
	taplo format

.PHONY: check-format
check-format: check-md ## Check Rust, TOML and markdown formatting
	cargo +$(NIGHTLY_RUST_VERSION) fmt --all -- --check
	taplo format --check

.PHONY: format-md
format-md: ## Format markdown with prettier
	npx --yes prettier@3 --write "**/*.md"

.PHONY: check-md
check-md: ## Check markdown formatting with prettier
	npx --yes prettier@3 --check "**/*.md"

.PHONY: lint
lint: ## Run clippy, warnings as errors
	cargo clippy --workspace --all-targets -- -D warnings

.PHONY: lint-beta
lint-beta: ## Run clippy with the beta toolchain
	cargo +beta clippy --workspace --all-targets -- -D warnings

# --- Python scripts ------------------------------------------------------
# The tools are pinned in pyproject.toml and uv.lock; the scripts themselves
# use the standard library only.

.PHONY: format-py
format-py: ## Format the Python scripts (ruff)
	uv run ruff format

.PHONY: check-format-py
check-format-py: ## Check the Python scripts' formatting (ruff)
	uv run ruff format --check

.PHONY: lint-py
lint-py: ## Lint the Python scripts (ruff)
	uv run ruff check

.PHONY: typecheck-py
typecheck-py: ## Type-check the Python scripts and their tests (mypy, strict)
	uv run mypy

.PHONY: test-py
test-py: ## Test the Python checks (pytest)
	uv run pytest

.PHONY: check-py
check-py: check-format-py lint-py typecheck-py test-py ## All Python checks

.PHONY: lint-shell
lint-shell: ## Lint shell scripts with shellcheck
	shellcheck $(SHELL_SCRIPTS)

.PHONY: check-where-clauses
check-where-clauses: ## Fail on trait bounds written inline, not in where
	find crates fuzz/fuzz_targets -name '*.rs' -not -path '*/target/*' \
		-print0 | xargs -0 python3 scripts/where_clauses.py

.PHONY: check-use-at-top
check-use-at-top: ## Fail on a `use` inside a function or block
	find crates fuzz/fuzz_targets -name '*.rs' -not -path '*/target/*' \
		-print0 | xargs -0 python3 scripts/use_at_top.py

.PHONY: check-opt-suffix
check-opt-suffix: ## Fail on a function returning an Option without _opt
	find crates fuzz/fuzz_targets -name '*.rs' -not -path '*/target/*' \
		-print0 | xargs -0 python3 scripts/opt_suffix.py

.PHONY: check-practices
check-practices: ## Fail if the README and the website list different practices
	python3 scripts/check_practices.py README.md website/src/practices.json

.PHONY: pkcs8-agreement
pkcs8-agreement: fixtures ## Check OPENSSL_3 and OPENSSL_4 write equal PKCS#8
	scripts/pkcs8-agreement.sh $(OPENSSL_3) $(OPENSSL_4)

.PHONY: check-urls
check-urls: doc ## Check every URL in the sources and the rendered docs
	python3 scripts/check_urls.py crates fuzz/fuzz_targets scripts README.md \
		Makefile .github website/index.html website/src target/doc

.PHONY: check-unsafe
check-unsafe: ## Fail if unsafe code appears outside baldssl-crypto's os_rng
	@found=$$(grep -rlE 'unsafe *(\{|fn|extern|impl)' crates fuzz \
		--include='*.rs' | grep -v '^crates/baldssl-crypto/src/os_rng.rs$$' \
		|| true); \
	if [ -n "$$found" ]; then \
		echo "unsafe code outside os_rng.rs:"; echo "$$found"; exit 1; \
	fi; \
	echo "unsafe code only in crates/baldssl-crypto/src/os_rng.rs"

.PHONY: check-no-deps
check-no-deps: ## Fail if any third-party crate is a normal/build dependency
	@external=$$(cargo tree --workspace -e normal,build --prefix none \
		--format '{p}' | sort -u | grep -v '^$$' | \
		grep -vE '\((/|[A-Za-z]:)' || true); \
	if [ -n "$$external" ]; then \
		echo "third-party dependencies are not allowed:"; \
		echo "$$external"; exit 1; \
	fi; \
	echo "no third-party dependencies"

# --- Tests -------------------------------------------------------------------

.PHONY: fixtures
fixtures: ## Download the pinned test fixtures into tests/fixtures
	scripts/fetch-fixtures.sh $(FIXTURES_TAG) $(FIXTURES_SHA256) \
		tests/fixtures

.PHONY: test
test: fixtures ## Run all tests (unit, property, golden)
	cargo test --workspace

.PHONY: test-release
test-release: fixtures ## Run all tests in release mode
	cargo test --workspace --release

# os_rng on every libc and OS version it supports. The versions CI tests are
# in website/src/platforms.json; the minimum versions are documented in
# crates/baldssl-crypto/src/os_rng.rs.
# Ubuntu 24.04 (noble), glibc 2.39.
IMAGE ?= buildpack-deps:noble
EXPECT ?= pass
MUSL_TARGET ?= x86_64-unknown-linux-musl
ANDROID_MODE ?= run
ANDROID_API ?= 28
ANDROID_RUN_API ?= 28

.PHONY: platform-matrix
platform-matrix: ## The os-rng CI matrices, from website/src/platforms.json
	python3 scripts/platform-matrix.py

.PHONY: ci-changes
ci-changes: ## The CI job groups a change needs (CHANGES_BASE=<rev>; none: all)
ifeq ($(CHANGES_BASE),)
	python3 scripts/ci-changes.py --all
else
	mkdir -p target
	git diff --name-only $(CHANGES_BASE) HEAD > target/changed-files
	python3 scripts/ci-changes.py target/changed-files
endif

.PHONY: test-os-rng
test-os-rng: ## Run the os_rng tests on this machine
	cargo test -p baldssl-crypto --lib os_rng

.PHONY: test-os-rng-glibc
test-os-rng-glibc: ## os_rng in a Linux container (IMAGE, EXPECT)
	scripts/test-os-rng-glibc.sh "$(IMAGE)" "$(EXPECT)"

.PHONY: test-os-rng-musl
test-os-rng-musl: ## os_rng statically linked against musl (MUSL_TARGET=)
	rustup target add "$(MUSL_TARGET)"
	cargo test -p baldssl-crypto --lib --target "$(MUSL_TARGET)" os_rng

.PHONY: test-os-rng-android
test-os-rng-android: ## os_rng on Android (ANDROID_MODE, ANDROID_API, _RUN_API)
	scripts/test-os-rng-android.sh "$(ANDROID_MODE)" "$(ANDROID_API)" \
		"$(ANDROID_RUN_API)"

.PHONY: test-os-rng-system-rust
test-os-rng-system-rust: ## os_rng with the OS's packaged Rust (BSD VMs)
	rustc --version
	cargo test --ignore-rust-version -p baldssl-crypto --lib os_rng

# The timeout is how long a test binary may go without a response. The
# instrumented debug build of the curve arithmetic is slow: its
# scalar-multiplication and key-generation tests can stay silent for more
# than tarpaulin's default of 60 seconds.
COVERAGE_TIMEOUT = 600

.PHONY: coverage
coverage: fixtures ## Coverage report (Cobertura XML + HTML) in target/coverage
	cargo tarpaulin --workspace --engine llvm --out Xml --out Html \
		--timeout $(COVERAGE_TIMEOUT) --output-dir target/coverage

.PHONY: mutants
mutants: fixtures ## Mutation testing (slow); survivors are missing tests
	cargo mutants --workspace

.PHONY: fuzz
fuzz: ## Fuzz a target: make fuzz FUZZ_TARGET=x509 FUZZ_SECONDS=60
	mkdir -p fuzz/corpus/$(FUZZ_TARGET)
	cd fuzz && cargo +$(NIGHTLY_RUST_VERSION) fuzz run $(FUZZ_TARGET) \
		corpus/$(FUZZ_TARGET) seeds/$(FUZZ_TARGET) \
		-- -max_total_time=$(FUZZ_SECONDS)

.PHONY: interop
interop: build fixtures ## Diff baldssl against $(OPENSSL), both directions
	scripts/interop.sh $(OPENSSL) $(BALDSSL)
	scripts/req-interop.sh $(OPENSSL) $(BALDSSL)
	scripts/x509-req-interop.sh $(OPENSSL) $(BALDSSL)
	scripts/pkey-interop.sh $(OPENSSL) $(BALDSSL)
	scripts/verify-interop.sh $(OPENSSL) $(BALDSSL)
	scripts/dgst-interop.sh $(OPENSSL) $(BALDSSL)
	@echo "interop: every suite passed against $$($(OPENSSL) version)."
	@echo "Another release: make interop OPENSSL=/path/to/openssl; the"
	@echo "profile follows its version (3.0, 3, 3.6 or 4). The releases CI"
	@echo "tests are in .github/workflows/ci.yml."

.PHONY: golden
golden: fixtures ## Regenerate golden files from OpenSSL 3.0, 3.5 and 4.1
	scripts/gen-golden.sh $(OPENSSL_30) $(OPENSSL_3) $(OPENSSL_4)

.PHONY: check-golden
check-golden: fixtures ## Fail if OpenSSL's output differs from the fixtures
	rm -rf target/golden-pinned && mkdir -p target
	cp -R tests/fixtures/golden target/golden-pinned
	scripts/gen-golden.sh $(OPENSSL_30) $(OPENSSL_3) $(OPENSSL_4)
	diff -r target/golden-pinned tests/fixtures/golden

.PHONY: objects
objects: ## Regenerate the OID name table from OPENSSL_INCLUDE/obj_mac.h
	scripts/gen-objects.py $(OPENSSL_INCLUDE)/openssl/obj_mac.h \
		"$$($(OPENSSL_3) version | awk '{print $$2}')" \
		> crates/baldssl-x509/src/objects_table.rs

# --- Website ----------------------------------------------------------------

.PHONY: website-install
website-install: ## Install the website build tools (npm ci)
	cd website && npm ci

.PHONY: website-dev
website-dev: ## Serve the website locally with live reload
	cd website && npx vite

.PHONY: website-build
website-build: ## Build the static website into website/dist
	cd website && npx vite build

.PHONY: website-examples
website-examples: build ## Run every command shown on the website ($(OPENSSL))
	scripts/check_website_examples.py --openssl $(OPENSSL) \
		--baldssl $(BALDSSL) $(if $(INSTALL),--install)

.PHONY: website-commands
website-commands: ## Regenerate website/src/commands.json from OpenSSL
	scripts/gen-commands.py $(OPENSSL_3) $(OPENSSL_4) \
		website/src/commands.json

# --- Lean 4 -----------------------------------------------------------------

.PHONY: lean
lean: ## Build the Lean 4 skeleton in proofs/ (Aeneas library, Mathlib cache)
	cd proofs && lake exe cache get && lake build

# --- Aggregate ---------------------------------------------------------------

.PHONY: ci
ci: check-format lint test doc doc-private check-no-deps check-unsafe \
	check-aeneas check-where-clauses check-use-at-top check-opt-suffix \
	check-practices lint-shell check-py ## Run the CI checks locally

.PHONY: clean
clean: ## Remove build artifacts
	cargo clean

.PHONY: setup
setup: ## Install the development tools
	rustup toolchain install $(NIGHTLY_RUST_VERSION) --component rustfmt
	rustup toolchain install beta --component clippy
	cargo install taplo-cli --version $(TAPLO_CLI_VERSION) --locked
	cargo install cargo-tarpaulin cargo-mutants cargo-fuzz --locked
