.PHONY: dependencies download-macos-installer download-catalina-installer
.PHONY: install do-install uninstall do-uninstall

dependencies: download-macos-installer
	brew bundle --no-lock --no-upgrade
	bundle install

os_version = $(shell sw_vers -productVersion)

download-macos-installer:
	@# Download the Catalina installer if we're on Catalina and we haven't already downloaded it
	@[[ ! "$(os_version)" =~ ^10\.15\. ]] || \
		[[ -d "/Applications/Install macOS Catalina.app" ]] || \
		$(MAKE) download-catalina-installer

download-catalina-installer:
	@echo "Downloading macOS Catalina installer to /Applications/"
	@# `softwareupdate` is Catalina only
	softwareupdate --fetch-full-installer --full-installer-version "$(os_version)"

check_box_command = vagrant box list | grep "^macinbox\s" | grep -w virtualbox > /dev/null

# Checks if the macinbox box exists for the specified provider.
install:
	@$(check_box_command) || $(MAKE) do-install

MACINBOX_ARGS ?= --no-gui --cpu 4 --memory 8192

do-install: dependencies
	@echo "Installing macinbox Vagrant box using VirtualBox"
	sudo bundle exec macinbox --box-format virtualbox $(MACINBOX_ARGS)

uninstall:
	@! $(check_box_command) || $(MAKE) do-uninstall

do-uninstall:
	vagrant box remove macinbox --provider virtualbox --all

# Maintenance commands

upgrade-deps:
	bundle update
