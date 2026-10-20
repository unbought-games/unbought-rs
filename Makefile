.PHONY: check test package-list publish-dry-run publish

check:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --locked -- -D warnings
	$(MAKE) test
	$(MAKE) publish-dry-run

test:
	cargo test --workspace --locked

package-list:
	cargo package -p unbought-auth --locked --list

publish-dry-run:
	cargo publish -p unbought-auth --locked --dry-run

publish:
	cargo publish -p unbought-auth --locked
