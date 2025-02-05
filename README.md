# win-certs

Use Python + ctypes to read certificates from the Windows certificate store.

Enumerate the certificates in the MY store, decode them to a simple
dataclass and call a callback filtering function.

When a certificate is selected, return the certificate + private key
(created using the cryptography library).
