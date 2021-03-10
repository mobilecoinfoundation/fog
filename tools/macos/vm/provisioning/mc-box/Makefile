.PHONY: install ensure-macinbox do-install package-box uninstall do-uninstall clean-temporaries

mc_box_name = mobilecoin
mc_box_tmp_path = /tmp/mobilecoin.box

check_mc_box_command = vagrant box list | grep "^$(mc_box_name)\s" | grep -w virtualbox > /dev/null
check_macinbox_command = vagrant box list | grep "^macinbox\s" | grep -w virtualbox > /dev/null

install:
	@$(check_mc_box_command) || $(MAKE) do-install

ensure-macinbox:
	@$(check_macinbox_command) || { >&2 echo "Error: Create macinbox Vagrant box first."; exit 1; }

do-install: ensure-macinbox clean-temporaries
	@echo "Installing mobilecoin Vagrant box using VirtualBox"
	vagrant up --provider virtualbox
	@$(MAKE) package-box clean-temporaries

package-box:
	@# Get Vagrantfile packaged by macinbox so it can be copied into the new box and
	@# package running VM into .box file
	vagrantfile="$$(find "$$HOME/.vagrant.d/boxes/macinbox" -name Vagrantfile | tail -n1)"; \
	vagrant package --output "$(mc_box_tmp_path)" --vagrantfile "$$vagrantfile"

	@# Add .box file to vagrant box list
	vagrant box add "$(mc_box_tmp_path)" --name "$(mc_box_name)"

uninstall: clean-temporaries
	@! $(check_mc_box_command) || $(MAKE) do-uninstall

do-uninstall:
	vagrant box remove "$(mc_box_name)" --provider virtualbox --all

clean-temporaries:
	vagrant destroy -f
	rm -r .vagrant 2>/dev/null || true
	rm "$(mc_box_tmp_path)" 2>/dev/null || true

# Maintenance commands

upgrade-deps:
	cd guest && bundle update
	cd guest && bundle exec xcversion update
	cd guest && bundle exec xcversion list | awk 'NF==1' | tail -1 > .xcode-version
