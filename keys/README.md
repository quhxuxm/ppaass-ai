# Local keys

Private keys in this directory are intentionally ignored by Git. The recommended desktop,
Windows, and Android flow is to sign in through Proxy Registry and let the Agent download its
approved user key into application-private storage.

Only Agent user credentials belong here. They are created and approved through Proxy Registry's
SQLite-backed account flow. Never commit private PEM files.
