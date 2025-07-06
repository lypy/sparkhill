# Sparkhill

Converts OpenPGP Curve25519/Ed25519/Ed25519Legacy secret to ssh secret

For RSA use monkeysphere (openpgp2ssh)/openssl

Use gpg-agent/ssh-add to convert in opposite direction.

```
gpg2 --export-secret-key $KEYID | \
  cargo run -- $KEYID | ssh-add /dev/stdin
```
