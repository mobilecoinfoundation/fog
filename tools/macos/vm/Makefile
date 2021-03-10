### Base box installation
.PHONY: dependencies install uninstall rebuild-mc-box

dependencies:
	brew bundle --no-lock --no-upgrade

install: dependencies
	@vagrant box list | grep "^mobilecoin\s" | grep -w virtualbox > /dev/null || $(MAKE) do-install

do-install:
	$(MAKE) -C provisioning/macinbox install
	$(MAKE) -C provisioning/mc-box install

uninstall: remove-vm
	$(MAKE) -C provisioning/macinbox uninstall
	$(MAKE) -C provisioning/mc-box uninstall

rebuild-mc-box: remove-vm
	$(MAKE) -C provisioning/mc-box uninstall install

### VM control
.PHONY: start stop remove-vm

start:
	vagrant up --provider virtualbox

stop:
	vagrant halt

remove-vm:
	vagrant destroy -f

### Build commands
.PHONY: macos-release macos-release-unsigned build-macos-release sign-macos-release copy-macos-release-app clean

VERSION ?= 0.0.1
KEYCHAIN ?=
CONSENSUS_ENCLAVE_CSS ?=

guest_build_dir = /Users/vagrant/build
guest_repo_dir = /Users/vagrant/internal
guest_output_dir = $(guest_repo_dir)/tools/macos/vm/out

macos-release: build-macos-release sign-macos-release

macos-release-unsigned: build-macos-release copy-macos-release-app

build-macos-release:
	@[[ -f "$(CONSENSUS_ENCLAVE_CSS)" ]] \
		|| { >&2 echo 'Error: `CONSENSUS_ENCLAVE_CSS` environment variable must refer to a file.'; exit 1; }

	@echo "Building macOS TestNet release"

	@# Copy consensus-enclave.css to VM
	$(eval consensus_enclave_css_guest_path := $(shell \
		vagrant upload --temporary "$(CONSENSUS_ENCLAVE_CSS)" \
			| sed -n 's/^.*Destination:[ \t]*\([^ \t].*\)$$/\1/p'))

	@vagrant ssh -c "cd $(guest_repo_dir)/src/testnet-client/macos && \
		./build-release \
		 	--release-version '$(VERSION)' \
		 	--consensus-enclave-css '$(consensus_enclave_css_guest_path)' \
			--cargo-target-dir '$(guest_build_dir)'" -- -q

# Hack: use LC_ prefix for environment variables to allow passthrough when using `vagrant ssh`
# See: https://stackoverflow.com/a/36126518/216311
sign-macos-release: export LC_KEYCHAIN_PASSWORD := $(KEYCHAIN_PASSWORD)
sign-macos-release:
	@[[ -f "$(KEYCHAIN)" ]] || \
		{ >&2 echo 'Error: `KEYCHAIN` environment variable must refer to a file.'; exit 1; }

	@echo "Signing macOS TestNet release"

	@# Copy keychain to VM
	$(eval keychain_guest_path := $(shell vagrant upload --temporary "$(KEYCHAIN)" \
		| sed -n 's/^.*Destination:[ \t]*\([^ \t].*\)$$/\1/p'))

	@mkdir -p out

	@# Sign and notarize .app, package as .dmg, then sign and notarize .dmg
	@vagrant ssh -c 'cd $(guest_repo_dir)/src/testnet-client/macos && \
		KEYCHAIN_PASSWORD="$$LC_KEYCHAIN_PASSWORD" \
		./package-release \
			--input "$(guest_build_dir)/release/MobileCoin TestNet.app" \
			--output "$(guest_output_dir)" \
			--keychain "$(keychain_guest_path)"' -- -q

copy-macos-release-app:
	@mkdir -p out
	@vagrant ssh -c "cp -R '$(guest_build_dir)/release/MobileCoin TestNet.app' \
		'$(guest_output_dir)/'" -- -q

clean:
	@rm -rf out 2>/dev/null || true

# Maintenance commands

upgrade-deps:
	$(MAKE) -C provisioning/macinbox upgrade-deps
	$(MAKE) -C provisioning/mc-box upgrade-deps
