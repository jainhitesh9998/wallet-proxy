# Security

## Reporting a vulnerability

Please report security problems privately, through GitHub's "Report a vulnerability" on this repository's Security
tab, rather than in a public issue. Include what is affected (the trust service, the client library, the wallet
core), how to reproduce it, and what an attacker gains.

Of particular interest: anything that makes the client library or the wallet trust a party, a key or a document the
registry does not vouch for; a difference between the service's and the library's decisions; a way to make the
proxy fetch from a private network; a way around client authentication.

## What is and is not a secret here

- `conformance/pki/` and `packages/wallet-core/test/fixtures/` hold **test keys**, committed on purpose. They protect
  nothing.
- The API keys in the shipped `application.yml` (`demo-wallet-key`, `admin-key`) are for the demo configuration. A
  deployment replaces them; see the production checklist in `docs/configuration.md`.
- The demo wallet (`apps/wallet`) uses software keys and no user authentication. It demonstrates the protocols and the
  trust layer; it is not a wallet to keep real credentials in.
