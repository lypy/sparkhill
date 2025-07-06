# Sparkhill

Converts OpenPGP Curve25519/Ed25519/Ed25519Legacy secret to ssh secret

For RSA use monkeysphere (openpgp2ssh)/openssl

Use gpg-agent/ssh-add to convert in opposite direction.

Example ssh CA issuing of user certificates from PGP web of trust

```
ssh-keygen -s /dev/stdin -I user@example.org id_file.pub \
  <<< "$(gpg --export-secret-key <pri key id> | \
  sparkhill <sub key id>)"
```
