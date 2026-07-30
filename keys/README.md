# Local keys

Private keys in this directory are intentionally ignored by Git. The recommended desktop,
Windows, and Android flow is to sign in through Proxy Registry and let the Agent download its approved
managed key into application-private storage.

For a local Proxy transport identity, generate a PKCS#8 private key and its SPKI public key:

```bash
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out keys/proxy-identity-private.pem
openssl pkey -in keys/proxy-identity-private.pem -pubout -out keys/proxy-identity-public.pem
```

Point Proxy at the private file and Proxy Registry at the public file. User credentials are created and
approved through Proxy Registry's SQLite-backed account flow. Never commit private PEM files.
