# pre
Go package for proxy re-encryption.

This package currently implements the AFGH scheme from 

[Improved Proxy Re-Encryption Schemes with Applications to Distributed
Storage](https://eprint.iacr.org/2005/028.pdf), by Giuseppe Ateniese, Kevin Fu,
Matthew Green, Susan Hohenberger, NDSS 2025


## Examples

### Single file example
`cmd/example/`

### Distributed system example (samba-lite)
- alice, bob, proxy, and sender in `cmd/`
- TODO:
    - go through all http response handlers, and make them catch and log any errors.
    - debug until operational!

