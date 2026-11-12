# Trust methods

How each way of trusting a party is configured in the trust service, what of it reaches the device, and how a
decision comes out of it. [architecture.md](architecture.md) explains the design and
[configuration.md](configuration.md) lists every setting; this guide goes method by method, with requests you can run.

A wallet meets a party through a signature. What that signature is checked against depends on the credential format
and the protocol, and so does what an operator has to list:

| Method | Used by | The operator lists | The device checks | When the service is away |
| --- | --- | --- | --- | --- |
| [X.509 chain](#x509-chains) | ISO mdoc / mDL (a Document Signer under an IACA), SD-JWT VC with `x5c`, OpenID4VP request signing, status list signers | Trust anchors (CA certificates), each in a trust domain | The chain up to an anchor of that domain, the certificate profile, revocation | The snapshot it holds; without one, anchors pinned in the app |
| [CRL](#crls) | Every certificate below an anchor | Where each CA publishes its CRL, or the CRL itself | Each certificate against a CRL signed by its issuer | The CRLs in the snapshot, then the distribution points |
| [Status list](#credential-status-lists) | Credentials: Token Status List (SD-JWT VC, mdoc), Bitstring Status List (W3C) | Nothing per list; optionally who else may sign lists | The list's signature and signer, then the credential's entry | The list's own URI |
| [DID](#dids) | W3C credentials with Data Integrity proofs; verifiers named by a DID | The DID, as an identifier of an entity | The key is in the DID document, under the right relationship | `did:key` and `did:jwk` on the device; `did:web` at its host |
| [Identifier and issuer metadata](#identifiers-and-issuer-metadata) | A credential offer, before any key is seen | The issuer's URL, as an identifier | A registry lookup; metadata signed by the service | Discovery at the issuer |
| [JSON-LD context](#json-ld-contexts) | Data Integrity proofs | The contexts an issuer's credentials use | The digest of each context document | The context's URL, reported as not vouched for |

Two more sections cover what these rest on: [where anchors and entities come from](#where-anchors-and-entities-come-from)
(a hand-written registry, the admin API, ETSI lists, a VICAL, OpenID Federation, EBSI) and
[trust pinned in the app](#trust-pinned-in-the-app). The last section maps
[each setting to its method](#which-setting-belongs-to-which-method).

## The example

The requests below run against [`docs/examples/trust-methods`](examples/trust-methods): a service configuration with
a lenient client (`wallet`), a strict one (`strict-wallet`) and an operator (`ops`), and a registry with one party
per method on the test certificates of [`conformance/pki`](../conformance/README.md).

From the repository root:

```sh
scripts/build.sh                                    # once
java -jar trust-server/trust-server/target/trust-server.jar \
  --spring.config.additional-location=docs/examples/trust-methods/application.yml       # http://localhost:8095
```

In a second terminal, also at the repository root (the answers are trimmed with `jq`):

```sh
x5c() { grep -v -- '-----' "conformance/pki/$1.pem" | tr -d '\n'; }       # a PEM certificate as an x5c entry
ask() { curl -s -H "Authorization: Bearer $1" -H 'Content-Type: application/json' localhost:8095/api/v1/evaluate -d "$2"; }
short='{decision, summary, reasons: [.reasons[] | "\(.severity) \(.code)"], revocation: [.evidence.x509.revocation[]? | {subject, status, reason}]}'
```

`ask` puts a question to the service's own evaluator, because `curl` is the quickest way to see a decision. A wallet
does not ask the service: the library answers the same question on the device, from the signed snapshot, by the
same rules (the [evaluation vectors](architecture.md#conformance) keep the two alike).
[`library.mjs`](examples/trust-methods/library.mjs) asks every question of this guide through the library:

```sh
node docs/examples/trust-methods/library.mjs            # decided on the device, from the service's snapshot
node docs/examples/trust-methods/library.mjs pinned     # no service: only trust pinned in the app
```

## X.509 chains

### What the operator lists

A **trust anchor**: a CA certificate, the **trust domain** it is an anchor for, optionally the entity it belongs
to, and constraints.

```yaml
anchors:
  - id: utopia-iaca
    domain: mdoc-iaca                       # what chains to this anchor are accepted for
    entity: utopia-dmv                      # a chain to this anchor is this party; omit for a CA shared by many
    certificateLocation: conformance/pki/iaca.pem     # or certificate: "<PEM>"
    constraints:
      docTypes: [org.iso.18013.5.1.mDL]     # an IACA: the doctypes it may sign
      crlUrls: ["https://pki.example.org/iaca.crl"]   # see CRLs
```

The domain is chosen by the question, never by the certificate, so an anchor of one domain cannot vouch in another:

| Question | Domain | Profile applied to the chain |
| --- | --- | --- |
| Issuer of an `mso_mdoc` credential | `mdoc-iaca` | The signer is not a CA and may sign (`digitalSignature`). For an mDL (and when the doctype is not given), ISO 18013-5 Annex B on top: extended key usage `1.0.18013.5.1.2`, and the signer's country is the IACA's |
| Issuer of any other format (`dc+sd-jwt` with `x5c`), signer of issuer metadata | `credential-issuer` | The signer may sign (`digitalSignature`) |
| Verifier (OpenID4VP request signer) | `verifier-access` | The signer is not a CA; for `x509_san_dns` the DNS name is a SAN of the leaf |
| Wallet provider, status list signer | `wallet-provider`, `status-list` | RFC 5280 only |

An anchor can be listed in four ways. They produce the same record:

| Way | For | See |
| --- | --- | --- |
| An `anchors:` entry in a registry file (`static` source) or sent to the admin API (`managed` source) | CAs you list yourself | [Registry format](configuration.md#registry-format), [admin API](configuration.md#admin-api) |
| `x509-bundle` source: a PEM / DER bundle; fetched over the network, each certificate must match a pinned SHA-256 | A CA bundle someone publishes | [Sources](configuration.md#frameworks-and-sources) |
| `vical` source | The IACAs of an mDL ecosystem, with their doctypes | [below](#where-anchors-and-entities-come-from) |
| `etsi-tl`, `etsi-lote` sources | EU trusted lists | [below](#where-anchors-and-entities-come-from) |

### How a chain is validated

The same steps run in the service (`X509PathValidator`) and in the library (`x509/validate.ts`).

1. **Shape.** Leaf first, at most 10 certificates. The anchor may be the last certificate or be left out (as `x5c`
   usually does). A single certificate that is itself listed as an anchor is accepted as pinned.
2. **Anchor.** Among the anchors of the domain, in the frameworks the client may see: the one whose subject is the
   issuer of the topmost certificate and whose key verifies it. No such anchor: the decision is `UNKNOWN`
   (`x509.no_anchor`), since nobody listed its CA; the wallet core then refuses the credential or the verifier,
   because a signature under an unknown CA proves nothing. The anchor must be active, within its own validity, a CA
   allowed to sign certificates, and the chain no longer than its path length allows (an IACA has path length 0: it
   signs Document Signers directly).
3. **RFC 5280** at the time of the check: signatures, validity periods, CA and path length constraints, key usage,
   critical extensions. A failure is reported as `x509.path.<reason>`.
4. **The profile of the domain** (table above) and the anchor's `docTypes`: a chain to an IACA listed for the mDL
   does not vouch for another doctype (`x509.anchor_doctype`).
5. **Revocation** of every certificate below the anchor: see [CRLs](#crls).

A chain that passes says the certificate is valid. **Whose** it is comes from the registry, through what the key
proves and never through what a credential claims: the entity its anchor belongs to (`entity:` on the anchor), or
an entity that lists the certificate, its subject, its subject key identifier, its SHA-256 hash or one of its DNS
names ([how to list a party](configuration.md#registry-format)). With an entity, its standing and its
authorizations are checked too. Without one, a valid chain is still `TRUSTED` ("validates to a trusted anchor"):
the CA vouches for it, and the wallet shows no registered name.

The outcome is `TRUSTED`, `UNKNOWN` or `NOT_TRUSTED` (any error), with every reason and the evidence.

### Try it

```sh
ask wallet-key '{"role": "issuer", "subject": {"x5c": ["'"$(x5c ds)"'"]},
  "context": {"credentialFormat": "mso_mdoc", "credentialType": "org.iso.18013.5.1.mDL"}}' | jq "$short"
```

```json
{
  "decision": "TRUSTED",
  "summary": "Trusted credential issuer 'Utopia DMV' in framework 'example'",
  "reasons": ["INFO x509.valid"],
  "revocation": [{ "subject": "CN=Utopia DS,O=Utopia DMV,C=UT", "status": "GOOD", "reason": null }]
}
```

The full answer also carries the entity, the anchor, each certificate of the path and what authorized the credential
type. Variations on the same registry:

| Question | Answer |
| --- | --- |
| The same chain for `"credentialType": "eu.europa.ec.eudi.pid.1"` | `NOT_TRUSTED`, `x509.anchor_doctype`: the IACA is listed for the mDL only |
| `$(x5c rogue-ds)`, signed by an IACA nobody listed | `UNKNOWN`, `x509.no_anchor` |
| `["$(x5c chain-leaf)", "$(x5c chain-ca)"]` with `"credentialFormat": "dc+sd-jwt"` | `TRUSTED` through the intermediate CA to `issuer-root` in `credential-issuer`, with warnings (see CRLs) |
| The same chain with `"identifier": "https://issuer.utopia.example"` | `NOT_TRUSTED`, `identifier.unbound`: the chain is valid, but that name is Utopia DMV's and this key is not bound to it |

### Verifiers

A verifier that signs its OpenID4VP request with a certificate names itself by a client identifier that the
certificate must prove:

- `x509_san_dns:<name>`: the name is a SAN `dNSName` of the leaf. The `response_uri` must be on that host, unless
  the verifier is registered (then a different host is a warning).
- `x509_hash:<hash>`: the hash is the SHA-256 of the leaf certificate.

```sh
ask wallet-key '{"role": "verifier", "subject": {"identifier": "x509_san_dns:verifier.example", "x5c": ["'"$(x5c rp)"'"]},
  "context": {"responseUri": "https://verifier.example/response"}}' | jq "$short"
# TRUSTED: "Trusted verifier 'Verifier Inc' in framework 'example'"
```

The CA here (`rp-access-ca`) is shared by many verifiers and belongs to none. This one is recognized as Verifier Inc
because the registry lists the DNS name its certificate carries.

### Reasons

| Code | Meaning |
| --- | --- |
| `x509.valid` | The chain validates to an anchor of the domain |
| `x509.no_anchor` | No anchor of the domain issued the topmost certificate: `UNKNOWN` |
| `x509.path.<reason>` | RFC 5280 validation failed (`expired`, `not_yet_valid`, `invalid_signature`, `invalid_key_usage`, `not_ca_cert`, `path_too_long`, `unrecognized_crit_ext`, ...) |
| `x509.chain_too_long` | More than 10 certificates |
| `x509.anchor_status`, `x509.anchor_expired`, `x509.anchor_not_ca`, `x509.anchor_path_length` | The anchor is withdrawn, outside its validity, not a signing CA, or the chain is deeper than it allows |
| `x509.anchor_doctype` | The anchor is not listed for the doctype |
| `mdoc.ds.eku`, `mdoc.ds.country`, `mdoc.ds.key_usage`, `mdoc.ds.is_ca` | The Document Signer profile |
| `issuer.key_usage`, `verifier.leaf_is_ca`, `verifier.san_dns` | The issuer and verifier profiles |
| `client_id.x509_hash_mismatch`, `client_id.san_dns_mismatch`, `client_id.response_uri_host`, `client_id.x5c_required` | The client identifier is not what the certificate proves |
| `identifier.unbound` | The identifier names a registered party that this key is not bound to |
| `x509.revoked`, `x509.on_hold`, `x509.revocation_unknown`, `x509.not_revoked` | Revocation: next section |

## CRLs

Every certificate below the anchor is looked up in a CRL signed by its issuer. OCSP is not used, by the service or
by the device: an OCSP request names the one certificate being checked, to a third party.

### Where a CRL comes from

| Certificate issued by | Its CRL | Configured with |
| --- | --- | --- |
| A trust anchor | Fetched by the service, verified, and shipped in the snapshot | On the anchor: `constraints.crlUrls`, or `constraints.crl` (a CRL the operator pushes: base64 DER, or PEM). With neither, a self-issued anchor's own CRL distribution point is used |
| A CA below an anchor | Fetched when a chain needs it, from the certificate's CRL distribution point | Nothing: the certificate names it |

```yaml
anchors:
  - id: utopia-iaca
    ...
    constraints:
      crlUrls: ["https://pki.example.org/iaca.crl"]    # fetched and refreshed by the service
      # or, for a service without outbound access (trust.revocation.fetch-anchor-crls: false):
      # crl: "MIIBWjCCAQAC..."                         # replaced by updating the entry
```

An anchor that is not a root (an intermediate CA listed as an anchor) needs `crlUrls`: the distribution point in its
own certificate is where the CA above it publishes, not where it does.

### What the service does

- Fetches each anchor's CRL and accepts it only if the anchor issued it: same issuer name, signature by the
  anchor's key.
- Refreshes it at the earlier of `trust.revocation.refresh` (1 h) and the CRL's next update. When a fetch fails it
  retries within five minutes and keeps the CRL it holds while that one is still current; the failure is logged
  (`CRL <url> for anchor <subject>: <reason>`).
- Refuses a CRL older than the one it holds (issued earlier, or with a lower CRL number): a CRL from before a
  revocation, served again, would take the revocation back.
- Ships the current CRL of every anchor a client can see in that client's snapshot (`crls`), up to
  `snapshot-max-crl-bytes` (256 KiB) each. A larger one is left out, and so is one that could not be loaded; a device
  then fetches the CRL itself, from the anchor's `crlUrls` for a certificate the anchor issued, or from a distribution
  point the certificate names. An anchor without `crlUrls` (its CRL pushed with `crl`, or found at its own
  distribution point) gives the device nowhere to look: raise the limit for such a CA whose certificates name no
  distribution point.
- Relays any other CRL: `GET /api/v1/proxy/crl?url=<distribution point>`, cached until the earlier of `refresh`
  and its next update. The relay passes on only what parses as a CRL, byte for byte, and does not verify it: it
  does not know the issuer, the device does.
- For its own decisions (`POST /api/v1/evaluate`) it fetches the CRLs of CAs below an anchor itself
  (`fetch-on-demand`).

### What the device does

- Checks each certificate against the CRLs in the snapshot first. No request leaves the device.
- For a certificate whose status is still unknown, fetches its CRL from the http(s) distribution points it names,
  and, for a certificate the trust anchor issued, from the http(s) URLs in the anchor's `constraints.crlUrls` (an
  anchor of the snapshot, or one pinned in the app). Each through the relay, and from the URL itself when the relay
  cannot serve (`lookups.crl`: `'proxy'`, `'direct'`, or `'none'` to never download one). Only chains that lead to a
  trusted anchor trigger a download.
- Verifies every CRL against the certificate's issuer, wherever it came from; one from an anchor's `crlUrls` counts
  only when the anchor issued it (the anchor's name as issuer, signed by its key). One that does not verify is not
  kept. A fetched CRL is kept until its next update (at most a day) and never replaced by an older one.
- A CRL scoped by an issuing distribution point covers only the certificates that name that point (see below), and
  this holds for a CRL from an anchor's `crlUrls` too: for a certificate that names no distribution point, the CA must
  publish there a CRL for all its certificates, one without an issuing distribution point or with one that names no
  location.

### How a status is decided

A CRL counts for a certificate when the certificate's issuer issued and signed it, that issuer may sign CRLs, it is
current (not issued in the future beyond five minutes of clock skew, not past its next update), it is a complete
CRL (no delta or indirect CRLs, none partitioned by reason, no critical extension the code does not know), and its
scope covers the certificate (its issuing distribution point, when it has one).

| Status | When | Reason code | Effect |
| --- | --- | --- | --- |
| `GOOD` | Such a CRL does not list the certificate | `x509.not_revoked` (info) | none |
| `REVOKED` | It lists the certificate | `x509.revoked` | `NOT_TRUSTED` |
| `ON_HOLD` | It lists the certificate with reason `certificateHold` | `x509.on_hold` | `NOT_TRUSTED` until the hold is lifted |
| `UNKNOWN` | No such CRL could be had: none is published, the download failed, the CA publishes only OCSP, or the CRL is of a kind that cannot be evaluated | `x509.revocation_unknown` | A warning; an error (`NOT_TRUSTED`) for a client profile with `require-revocation-status: true` |

The device is stricter than the service in two places: when it holds several CRLs for a certificate, a revocation
in any of them stands and otherwise the newest decides; and a CRL that states no next update is used for seven
days after it was issued, not indefinitely.

### Try it

```sh
ask wallet-key '{"role": "issuer", "subject": {"x5c": ["'"$(x5c ds-revoked)"'"]},
  "context": {"credentialFormat": "mso_mdoc", "credentialType": "org.iso.18013.5.1.mDL"}}' | jq "$short"
```

```json
{
  "decision": "NOT_TRUSTED",
  "summary": "Certificate 0 (CN=Utopia DS (revoked),O=Utopia DMV,C=UT) was revoked on 2026-11-01T04:46:22Z (keyCompromise)",
  "reasons": ["ERROR x509.revoked"],
  "revocation": [{ "subject": "CN=Utopia DS (revoked),O=Utopia DMV,C=UT", "status": "REVOKED", "reason": "keyCompromise" }]
}
```

`$(x5c ds-hold)` answers `x509.on_hold`. The chain under the intermediate CA has no CRL published at all, which
shows the two client profiles apart:

```sh
chain='{"role": "issuer", "subject": {"x5c": ["'"$(x5c chain-leaf)"'", "'"$(x5c chain-ca)"'"]}, "context": {"credentialFormat": "dc+sd-jwt"}}'
ask wallet-key "$chain" | jq -c '[.decision, .reasons[].code]'     # ["TRUSTED","x509.valid","x509.revocation_unknown","x509.revocation_unknown"]
ask strict-key "$chain" | jq -c '[.decision, .reasons[].code]'     # ["NOT_TRUSTED","x509.revocation_unknown","x509.revocation_unknown"]
```

What a device is given: the CRLs in its snapshot, and the relay.

```sh
curl -s -H 'Authorization: Bearer wallet-key' -H 'Accept: application/jwt' localhost:8095/api/v1/snapshot \
  | python3 -c 'import sys, json, base64
p = sys.stdin.read().split(".")[1]
claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
for c in claims["crls"]: print({k: v for k, v in c.items() if k != "crl"})'
# {'issuer': 'zQYvloYZ3gFN118CWOIHxIjm6WW87sfCQULlUuFfvBw', 'thisUpdate': '2026-11-01T04:46:22Z', 'nextUpdate': '2045-12-31T04:46:22Z', 'crlNumber': '1'}

# Any other CRL, by its distribution point (URL-encoded; this one is a placeholder). The answer is the CRL itself.
curl -s -o iaca.crl -H 'Authorization: Bearer wallet-key' 'localhost:8095/api/v1/proxy/crl?url=https%3A%2F%2Fpki.example.org%2Fiaca.crl'
```

`issuer` is the SHA-256 thumbprint of the anchor certificate the CRL belongs to; a CRL fetched from `crlUrls` also
carries its `url`. A relay request that cannot be served answers with a problem document: `502 upstream_unavailable`
when the distribution point does not answer, `502 invalid_crl` when what it serves is not a CRL.

### Checking that it works

- A decision's evidence (`evidence.x509.revocation`) names, per certificate, the status, the CRL it came from
  (`crlUrl`, absent for a pushed CRL), its `thisUpdate` and `nextUpdate`, and where the CRL was held (`source`:
  `trust-service` for the service's own decisions; `snapshot`, `proxy`, `direct`, `fallback` or `cache` on a device).
- The library's `status()` gives the number of CRLs in the snapshot in use (`snapshot.crls`).
- A CRL that could not be loaded is in the service log at `WARN`; the snapshot is then built without it and devices
  fall back to the distribution point. `GET /admin/v1/crls` (an admin client) shows every anchor CRL the service is
  responsible for: the anchors that use it, its `url` (absent for a pushed CRL), the dates and number of the CRL held,
  when it was fetched (`fetchedAt`) and will be next (`nextFetch`), the last `error`, whether the CRL held is
  `current`, and whether snapshots carry it (`inSnapshots`: current and no larger than `snapshot-max-crl-bytes`). An
  entry with `inSnapshots: false` is a CRL devices do not get from the service. In the example,
  `curl -s -H 'Authorization: Bearer ops-key' localhost:8095/admin/v1/crls` lists the CRL pushed with `utopia-iaca`:
  `"crlNumber": "1", "revoked": 2, "current": true, "inSnapshots": true`, and no `url` or `error`.

## Credential status lists

A CRL says whether a signer's certificate was revoked. A status list says whether one credential was: the credential
names a list and an index in it.

| List | Credential | Named by |
| --- | --- | --- |
| Token Status List, `statuslist+jwt` | SD-JWT VC | `status.status_list: { idx, uri }` |
| Token Status List, `statuslist+cwt` | ISO mdoc | `status.status_list` in the MSO |
| Bitstring Status List (and `StatusList2021`) | W3C credentials | `credentialStatus`: `statusListCredential`, `statusListIndex`, `statusPurpose` |

**Configuration.** Nothing is listed per status list: the credential names it, and it is signed. The service relays
lists (`GET /api/v1/proxy/status-list?uri=`), so that the issuer sees the service and not the device; only the list's
URI is sent, never the index. The relay passes on only a document that has the shape of a status list, caches it for
as long as the issuer allows within `status-list-max-ttl` (1 h; `status-list-default-ttl`, 5 min, when the issuer says
nothing), and can be switched off (`relay-status-lists`). In the library, `lookups.statusLists` is `'proxy'` (relay
first, then the list's URI) or `'direct'`.

**How the device checks a Token Status List** (`checkTokenStatus`):

1. Fetches the list and verifies its signature.
2. Checks **who signed it**. Accepted are: the credential's own signing certificate; a certificate issued under
   the trust anchor the credential's chain validated to; a certificate that validates in the `status-list` domain
   (a status provider trusted in its own right: list its CA as an anchor of that domain); or, for a list without a
   certificate, the credential's own signing key.
3. Checks that the list is the one named (`sub` equals the URI) and current: not expired, not issued in the future.
   A list that states no expiry is accepted for seven days after it was issued.
4. Reads the entry: `0` valid, `1` revoked, `2` suspended; another value is application specific and reported as
   unknown.
5. Reuses the verified list for its `ttl` (five minutes when it states none, an hour at most).

**A Bitstring Status List** (`checkBitstringStatus`) is itself a credential. It counts only when its proof verifies,
it was issued by the issuer of the credential it speaks for, it is a list for the entry's `statusPurpose`, it is
within its validity period, and it holds at least 131,072 entries (the minimum of the specification, so that an index
does not single out a holder). A set bit means revoked, or suspended when the purpose is `suspension`.

**Result.** `valid`, `revoked`, `suspended` or `unknown`, with the reason. A list that cannot be fetched or does not
verify never yields `valid`. The wallet core fails a credential that is revoked or suspended and warns about one
whose status is unknown.

```ts
const s = await trust.checkTokenStatus({ idx, uri }, { signerX5c: x5c, decision });        // SD-JWT VC; { form: 'cwt' } for an mdoc
// { status: 'valid', value: 0, detail: 'Index 7: VALID (statuslist+jwt, signer the credential signer (via the trust service relay))', ttlMs: 300000 }
```

## DIDs

**What the operator lists.** The DID, as an identifier of the entity. A credential (or request) signed with a key of
that DID is then that party's.

```yaml
entities:
  - id: example-university
    roles: [CREDENTIAL_ISSUER]
    identifiers:
      - did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK      # or did:web:issuer.example.org, did:ebsi:...
    authorizations:
      - { format: ldp_vc, type: UniversityDegreeCredential }
```

**How DIDs are resolved.**

| Method | Service | Device |
| --- | --- | --- |
| `did:key`, `did:jwk` | Computed from the DID | Computed on the device; nothing is fetched |
| `did:web` | `https://<host>/.well-known/did.json` or `https://<host>/<path>/did.json`. The DID may name a host (with a port) and plain path segments, nothing else | From the snapshot if listed; else the relay; else the same URL |
| `did:ebsi`, other registry methods | `trust.did.registries.<method>`: a URL template with `{did}` | From the snapshot if listed; else the relay |
| Any other | `trust.did.universal-resolver-url`, when configured; otherwise not resolvable | The relay |

The service resolves the DIDs it lists and ships their documents in the snapshot (`didDocuments`), so a decision
about a listed party needs no lookup. For a listed DID the snapshot is the resolver: when its document lacks the key
a credential names, the library fetches a fresh snapshot once, and does not go to the DID's host while it holds a
snapshot that is not expired. DIDs the snapshot does not carry go through `GET /api/v1/proxy/did/{did}` (the answer
is signed by the service and bound to the DID asked for), and by the method itself when the relay cannot serve
(`lookups.did`).

**The decision.** The key that signed (`kid`, a DID URL) must be a verification method of the DID document and be
listed under `assertionMethod` for an issuer, `authentication` for a verifier.

```sh
did=did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
ask wallet-key '{"role": "issuer", "subject": {"identifier": "'$did'", "kid": "'$did'#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"},
  "context": {"credentialFormat": "ldp_vc", "credentialType": "UniversityDegreeCredential"}}' | jq -c '[.decision, .summary]'
# ["TRUSTED","Trusted credential issuer 'Example University' in framework 'example'"]
```

| Code | Meaning |
| --- | --- |
| `did.vm_not_found` | The key is not in the DID document (`"kid": "'$did'#missing"`): `NOT_TRUSTED` |
| `did.relationship` | The key is in the document but not listed for `assertionMethod` / `authentication`: `NOT_TRUSTED` |
| `did.unresolved` | The DID document could not be read, so the key's place in it was not checked: a warning |
| `did.invalid` | The `kid` is not a DID URL: `NOT_TRUSTED` |
| `entity.not_authorized` | The party is not registered for the credential type (`"credentialType": "PidCredential"`) |

Settings: `trust.service.snapshot-did-documents`, `snapshot-max-did-documents`, `snapshot-did-deadline`;
`trust.cache.did-ttl`; `trust.did.*`; `trust.http.http-allowed-hosts` for a `did:web` on plain http in development
([configuration](configuration.md#proxy-cache-and-outbound-http)).

## Identifiers and issuer metadata

Before any key is seen, as with a credential offer that names a `credential_issuer`, the question is a registry
lookup: is this identifier listed, in good standing, in a framework this client sees?

```yaml
entities:
  - id: utopia-dmv
    roles: [CREDENTIAL_ISSUER]
    identifiers:
      - { type: URL, value: "https://issuer.utopia.example" }     # exactly as the issuer writes it
```

```sh
ask wallet-key '{"role": "issuer", "subject": {"identifier": "https://issuer.utopia.example"}}' | jq -c '[.decision, .summary]'
# ["TRUSTED","Trusted credential issuer 'Utopia DMV' in framework 'example'"]
ask wallet-key '{"role": "issuer", "subject": {"identifier": "https://nobody.example"}}' | jq -r .decision       # UNKNOWN
```

URLs are compared byte for byte, as OpenID4VCI compares them: no normalization, no trailing slash added or removed.
The wallet turns away an issuer that is `NOT_TRUSTED` before fetching anything from it, and asks the user before
going on with one that is `UNKNOWN`.

An identifier alone proves nothing once a key is on the table. When a credential arrives, the question is asked
again with the key that signed it, and the identifier becomes a claim that the key must back
(`identifier.unbound` otherwise). This is why a party is listed with something its key proves (its anchor, its
certificate, its DID), not only with its URL.

**Issuer metadata.** `trust.getIssuerMetadata(issuer)` fetches the OpenID4VCI metadata of the issuer and of its
authorization servers:

- Through the service: `GET /api/v1/proxy/issuer-metadata?issuer=`. The answer is signed by the service for this
  client and names the issuer asked for; the service applies the entity's `metadataPolicy`. It serves only issuers
  listed in the client's frameworks, unless the client profile has `allow-unregistered-metadata: true`.
- From the issuer itself (OpenID4VCI discovery) when the service cannot serve, or with `lookups.metadata: 'direct'`.
  The policy from the snapshot is applied on the device.
- **Signed issuer metadata**: with `issuerMetadata.signed: 'verify'` the library uses the issuer's signed metadata
  when there is one, with `'require'` it refuses issuers without it; a client profile with
  `require-signed-issuer-metadata: true` forces `'require'`. The signer's chain must validate in the
  `credential-issuer` domain and must not be self-signed. It is verified on the device, whoever relayed it.

## JSON-LD contexts

A Data Integrity proof signs the RDF form of a credential, and the contexts decide what that form is: whoever
controls a context document controls what the signature covers. The contexts of listed issuers therefore travel in
the snapshot.

```yaml
entities:
  - id: example-university
    contexts:
      - https://issuer.example.org/contexts/v1
      - { url: "https://issuer.example.org/contexts/v2", sha256: "<base64url digest>" }    # pinned: other content is not shipped
```

An `oid4vci-discovery` source adds the contexts that a listed issuer's metadata names. The service fetches each
context and puts it into the snapshot (`contexts`): the document itself up to `snapshot-max-context-bytes` in
total, past that its digest only.

On the device, `trust.context(url)` returns the document from the snapshot; one that the snapshot knows by digest
only is fetched from its URL and must have that digest; one the snapshot does not know at all is fetched and
returned with `vouched: false`, which the wallet core reports as a warning on the credential.

## Where anchors and entities come from

Anchors and entities reach the registry through **sources**, each in one framework
([configuration](configuration.md#frameworks-and-sources) has the properties of each type and what authenticates it).
The methods above work the same whatever the source.

| Source `type` | Becomes | Notes |
| --- | --- | --- |
| `static`, `managed` | Whatever the entries say | The [registry format](configuration.md#registry-format), from a file or through the admin API |
| `x509-bundle` | Anchors of one `domain` | No entities: list those separately, or name one with `entity` |
| `vical` (ISO 18013-5 VICAL) | Each IACA as an `mdoc-iaca` anchor constrained to its doctypes, each issuing authority as an entity that the anchor belongs to | The list is a COSE signature by the VICAL provider: pin its certificate with `signerCertificates` |
| `etsi-tl` (TS 119 612, EU LOTL) | Each provider as an entity, each service certificate as an anchor | Service types map to domains: EAA, QEAA and Pub-EAA services to `credential-issuer`; add or change with `serviceTypeDomains`. Other types are skipped unless `includeAllServiceTypes` (domain `etsi-<type>`). The anchor of a service whose status is not a granted or supervised one is listed as revoked |
| `etsi-lote` (TS 119 602) | The same, for the EUDI lists | PID and Pub-EAA providers: `credential-issuer` and `mdoc-iaca`; wallet providers: `wallet-provider`; access certificate CAs (WRPAC): `verifier-access`; the revocation services of each: `status-list` |
| `openid-federation` | Entities from validated trust chains, with their metadata policy | Can also be asked on demand about an entity identifier it did not crawl |
| `ebsi-tir` | `did:ebsi` issuers with what they are accredited for | Asked on demand by default |
| `oid4vci-discovery` | Display names and contexts of issuers that are listed elsewhere | Authorizes nothing |

**Parties too many to ship.** A federation or EBSI is not copied into every snapshot. With
`lookups.unknownParties: true` the library asks the service about an identifier the snapshot does not carry
(`GET /api/v1/entities/lookup`): only the identifier is sent, the answer is a signed registry entry, and the device
evaluates it like any other. It is off by default because it tells the service which party the user is dealing with.

## Trust pinned in the app

```ts
const trust = createTrustClient({
  service: { ... },
  pinned: { anchors: [{ domain: 'mdoc-iaca', certificate: IACA_PEM, constraints: { docTypes: ['org.iso.18013.5.1.mDL'] } }] },
});
```

Pinned anchors and entities decide only while no snapshot is usable: before the first one was fetched, or once the
held one is past its expiry and its grace period. With a snapshot, the service is the authority and a pinned anchor
overrides nothing. A decision from pinned trust says so (`source: 'pinned'`, warning `local.pinned`).

Pinned trust has no CRLs of its own and no client profile of its own. Revocation then rests on the certificates'
distribution points and on the pinned anchor's `constraints.crlUrls`, which are fetched as for an anchor of the
snapshot (see [CRLs](#crls), `lookups.crl`). The rules do not lapse with the snapshot: a decision from pinned trust is
made under the rules in force, which are the app's own minimum (the library option `policy`) made stricter by the
client profile of the last snapshot that verified. A profile with `require-revocation-status`, `strict-authorization` or
`require-signed-issuer-metadata` therefore stays strict after its snapshot has expired, also when the app restarts;
only the snapshot's data (its anchors, entities and CRLs) is no longer used. Rules are taken only from a snapshot whose
signature and audience verify against the pinned service keys: a store that was cleared, or that holds a snapshot that
no longer verifies, states none. An app that must stay strict whatever happens to its storage states its own minimum.
`status().rules` says which rules are in force.

```sh
node docs/examples/trust-methods/library.mjs pinned          # rules in force: none
node docs/examples/trust-methods/library.mjs pinned strict   # policy: { requireRevocationStatus: true }
```

The distribution point of the revoked Document Signer does not answer, so its status is unknown: without rules it is
`TRUSTED` with the warning `x509.revocation_unknown`; with the app's minimum it is `NOT_TRUSTED`, and so is the
Document Signer that names no distribution point at all.

## Which setting belongs to which method

| Method | Service | Client profile | Library |
| --- | --- | --- | --- |
| X.509 chains | Anchors (`domain`, `entity`, `constraints.docTypes`) from any source | `frameworks`, `strict-authorization` | `pinned.anchors`, `policy.strictAuthorization` |
| CRLs | Anchor `constraints.crlUrls` / `crl`; `trust.revocation.enabled`, `refresh`, `fetch-anchor-crls`, `fetch-on-demand`, `relay-crls`, `max-crl-bytes`, `snapshot-max-crl-bytes` | `require-revocation-status` | `lookups.crl`, `policy.requireRevocationStatus`; `constraints.crlUrls` of `pinned.anchors` |
| Status lists | `trust.revocation.relay-status-lists`, `status-list-default-ttl`, `status-list-max-ttl`, `max-status-list-bytes`; anchors of domain `status-list` | | `lookups.statusLists` |
| DIDs | Entity identifiers; `trust.service.snapshot-did-documents` and its limits; `trust.did.*`; `trust.cache.did-ttl` | | `lookups.did` |
| Identifiers, issuer metadata | Entity identifiers, `metadataPolicy`; `trust.cache.metadata-*` | `allow-unregistered-metadata`, `require-signed-issuer-metadata` | `lookups.metadata`, `issuerMetadata.signed`, `policy.requireSignedIssuerMetadata` |
| JSON-LD contexts | Entity `contexts`, `oid4vci-discovery` sources; `trust.service.snapshot-max-context-bytes`; `trust.cache.context-ttl` | | |
| Unknown parties | `openid-federation`, `ebsi-tir` sources | | `lookups.unknownParties` |

The service properties are described in [configuration.md](configuration.md#trust-service), the library options in
[its section there](configuration.md#client-library).
