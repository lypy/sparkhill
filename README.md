# Sparkhill

A command-line utility that bridges the gap between PGP and SSH identities. It extracts modern elliptic curve secret keys from an OpenPGP key block and converts them directly into the OpenSSH private key format.

This is particularly useful for infrastructure management and automation, allowing you to leverage an existing PGP Web of Trust to provision SSH access (for example issuing short lived SSH Certificate Authority user certificates).

#### Notes

* Converts OpenPGP Curve25519, Ed25519 or Ed25519Legacy to an ssh secret
* For RSA use monkeysphere (openpgp2ssh)
* pgp2ssh is an established alternative that has an interactive wizard.
* To convert an SSH key back into a PGP format, utilise gpg-agent alongside ssh-add.

## Usage Examples

To convert a key or generate an SSH certificate, first extract your secret PGP key block. You can achieve this using standard GnuPG or something like openpgp.js.

### Option 1: GnuPG

**Note:** While GnuPG a flag for exporting secret SSH keys directly, the underlying framework remains incomplete for elliptic curves. The GnuPG development team is currently tracking the finalisation of this feature under ticket T6647, slated for the 2.6 release cycle.

```
gpg --export-secret-key <primary key-id> > exported-key.gpg
```

### Option 2: openpgp.js

Simple example app to grab material

```
import { readFileSync } from 'node:fs';
import process from 'node:process';
import * as openpgp from 'openpgp';

const keyData = readFileSync(process.argv[2]);

const privateKeys = await openpgp.readPrivateKeys({ binaryKeys: keyData });

const targetKey = privateKeys.find(key => 
    key.getKeyID().toHex().toLowerCase() === process.argv[3].toLowerCase()
);

if (!targetKey) {
    process.exit(1);
}

const binaryData = targetKey.write();
process.stdout.write(binaryData);
```

```
deno run --allow-read export-key.js my-keys.gpg <primary-key-id> > exported-key.gpg
```


### Generating the SSH Certificate

Using the exported-key.gpg file generated from either method above, run the following pipeline:

```
ssh-keygen -s /dev/stdin -I user@example.org id_file.pub \
  <<< "$(cat exported-key.gpg | sparkhill <sub-key-id>)"
```

### Single-Line Execution

#### Using GnuPG:

```
ssh-keygen -s /dev/stdin -I user@example.org id_file.pub \
  <<< "$(gpg --export-secret-key <primary-key-id> | sparkhill <sub-key-id>)"
```

### Using js:

```
ssh-keygen -s /dev/stdin -I user@example.org id_file.pub \
  <<< "$(deno run --allow-read export-key.js my-keys.gpg <primary-key-id> | sparkhill <sub-key-id>)"
```
