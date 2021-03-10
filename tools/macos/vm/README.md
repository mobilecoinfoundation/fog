# macOS Build Environment

## Install

#### Prerequisites

* Download macOS installer to `/Applications/`
  * Downloadable from Mac App Store. See [macinbox documentation](https://github.com/bacongravy/macinbox#macos-installer) for more info.

#### App Store Connect credentials

Apple App Store Connect credentials are needed to download Xcode within the VM, which you will need to provide when provisioning the MobileCoin `mc-box` Vagrant box (e.g. as part of `make install` or `make install-mc-box`). This can be done in 1 of 2 ways:
* (Recommended) Via a `.env` file:
  * Within the `tools/macos/vm/provisioning/mc-box/guest/` folder copy `.env.example` to `.env`. Replace the values with your App Store Connect username and password.
* Via environment variables:
  * During the install step where `mc-box` is provisioned (e.g. `make install`), set the environment variables `XCODE_INSTALL_USER` and `XCODE_INSTALL_PASSWORD` to your App Store Connect username and password.

#### Steps

Default settings using VirtualBox:
```sh
make install
```

#### Customizations:

Custom macinbox (e.g. for different VirtualBox VM settings, or to use Parallels or VMWare Fusion instead of VirtualBox):
* Build macinbox Vagrant box (See [macinbox documentation](https://github.com/bacongravy/macinbox#basic-usage))
* Build MobileCoin Vagrant box
  * `make dependencies install-mc-box`

## Running

This local internal.git repo will be mounted at `~/internal` within the VM. Changes will be automatically synced between the VM and host while the VM is running.

#### Start VM:

```sh
make start
```

#### Stop VM:

```sh
make stop
```

#### Reset VM:

```sh
make remove-vm start
```

#### Building macOS TestNet client:

```sh
VERSION=<release-version> KEYCHAIN=<keychain-path> KEYCHAIN_PASSWORD=<keychain-password> make macos-release
```

Result: `MobileCoin TestNet.dmg` will be located in `./out/`.
  
#### Custom commands can be executed within the VM using SSH:

```sh
vagrant ssh
```

## Notes
 
 * Skip sudo password prompt when mounting vagrant: https://www.vagrantup.com/docs/synced-folders/nfs.html#root-privilege-requirement
 * Skip sudo password prompt when building macinbox base OS box:
```sh
echo "Cmnd_Alias MACINBOX_BUILD = $HOME/.rbenv/shims/bundle exec macinbox --box-format virtualbox --no-gui --cpu 4 --memory 8192\n%admin ALL=(root) NOPASSWD: MACINBOX_BUILD" | sudo EDITOR='tee' visudo /etc/sudoers.d/macinbox
```

## Troubleshooting

* If you encounter build issues when installing `virtualbox` via `Homebrew` (e.g. during `make install`), you may need to allow permissions in `Preferences`. According to VirtualBox:

```
virtualbox requires a kernel extension to work.
If the installation fails, retry after you enable it in:
  System Preferences → Security & Privacy → General

For more information, refer to vendor documentation or this Apple Technical Note:
  https://developer.apple.com/library/content/technotes/tn2459/_index.html
```

