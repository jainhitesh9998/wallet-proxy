# Contributing

## Build and test

```sh
. scripts/env.sh                 # optional: a user-local JDK 21 / Maven / Node 22 under ~/.local/tools
scripts/build.sh                 # service (with tests) and TypeScript packages
scripts/test-all.sh --offline    # every suite that needs no network
scripts/dev-up.sh                # trust service, reference issuer and verifier, for the live suites and the demo wallet
scripts/test-all.sh              # everything, including the live suites
```

CI runs the offline suites on every pull request.

## The rules of the house

- **The two evaluators stay in step.** A change to how trust is decided is made in `TrustEvaluator.java` and in
  `packages/trust-client/src/evaluation/local.ts` together, with a case in `conformance/evaluation/cases.json`, and
  the vectors regenerated (`conformance/README.md`). Review the vector diff: it is the change in behaviour.
- **Strict means strict.** A check a specification requires is not relaxed to make an issuer, a verifier or a test
  pass. If a real system needs different behaviour, that is a finding to discuss, with the specification text.
- **Nothing is trusted for where it came from.** New lookups through the proxy need a way for the device to verify
  the answer, and a standard-mechanism fallback.
- **The reference ecosystem stays on third-party implementations.** Do not reimplement in `test-ecosystem/` what a
  maintained library does.
- **Test what the change is about.** A new refusal gets a test that breaks exactly that rule; a new acceptance gets a
  test with a credential or certificate this repository did not produce where one can be had.

## Style

- Java 21, 4 spaces; TypeScript (ES modules, strict), 2 spaces; lines up to about 160 characters.
- Comments say why, in plain words, and cite the specification section a rule comes from.
- Commit messages: an imperative subject line of at most 72 characters, then what changed and why.
