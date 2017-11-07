# cryptctl
cryptctl is a utility for setting up disk encryption using the popular well-established LUKS method. It generates random
numbers to use as encryption keys, and safely keep the keys on a centralised key server. It can encrypt arbitrary
directories into encrypted disk partitions.

The key server stores all encryption keys in a database directory (by default /var/lib/cryptctl/keydb) and serves the
keys via an RPC protocol over TCP (by default on port 3737) to client computers. The key server is the central component
of encryption setup, hence it must be deployed with extra physical/network security measures; regular backup of the key
database must be carried out to ensure its availability. Communication between key server and client computers is
protected by TLS via a certificate, and authorised via a password specified by the system administrator during key
server's initial setup.

The encryption routine sets up encrypted file systems using using aes-xts-plain64 cipher, with a fixed-size (512-bit)
key generated from cryptography random pool. Encrypted directories will always be mounted automatically upon system boot
by retrieving their encryption keys from key server automatically; this operation tolerates temporary network failure or
key server down time by making continuous attempts until success, for maximum of 24 hours.

The system administrator can define an upper limit number of computers that can get hold of a key simultaneously. After
a client computer successfully retrieves a key, it will keep reporting back to key server that it is online, and the
key server closely tracks its IP, host name, and timestamp, in order to determine number of computers actively using
the key; if the upper limit number of computers is reached, the key will no longer be handed out automatically; system
administrator can always retrieve encryption keys by using key server's access password.

cryptctl can optionally utilise an external key management appliance that understands KMIP v1.3 to store the actual disk
encryption keys. Should you choose to use the external appliance, you may enter KMIP connectivity details such as host
name, port, certificate, and user credentials during server initialisation sequence. If you do not wish to use the
external appliance, cryptctl will store encryption keys in its own database.

To experiment with cryptctl features, you may temporary deploy both key server and encrypted partition on the same
computer; keep in mind that doing defeats the objective of separating key data from encrypted data, therefore always
deploy key server stand-alone in QA and production scenarios.

cryptctl is commercially supported by "SUSE Linux Enterprise Server For SAP Applications".

## Usage
Build cryptctl with go 1.8 or newer versions. It solely depends on Go standard library, no 3rd party library is used.

Install cryptctl binary along with configuration files and systemd services from `ospackage/` directory to both key
server and client computers. Then, please carefully read the manual page `ospackage/man/cryptctl.8` for setup and usage
instructions. 

## RPM package
A ready made RPM spec file and RPM package can be found here:
https://build.opensuse.org/package/show/security/cryptctl

## License
cryptctl is an open source free software, you may redistribute it and/or modify it under the terms of the GNU General
Public License version 3 as published by the Free Software Foundation.

See `LICENSE` file for the complete licensing terms and conditions.