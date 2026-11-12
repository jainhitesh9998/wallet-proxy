// The device side of docs/trust-methods.md: the same questions, decided by the client library from the snapshot.
// From the repository root, with the example service running (see application.yml) and the packages built:
//
//   node docs/examples/trust-methods/library.mjs                  # decisions from the service's snapshot
//   node docs/examples/trust-methods/library.mjs pinned           # no service: only trust pinned in the app
//   node docs/examples/trust-methods/library.mjs pinned strict    # the same, with the app's own minimum rules
import { readFileSync } from 'node:fs';
import { createTrustClient } from '@vctrust/trust-client';

const pem = (name) => readFileSync(`conformance/pki/${name}.pem`, 'utf8');
const x5c = (name) => pem(name).replace(/-----[^-]+-----|\s/g, '');     // a PEM certificate as an x5c entry
const mdl = { credentialFormat: 'mso_mdoc', credentialType: 'org.iso.18013.5.1.mDL' };

const show = (what, d) => {
  console.log(`${what}: ${d.decision} (decided from: ${d.source}${d.evidence?.mechanism ? `, under mechanism ${d.evidence.mechanism}` : ''})`);
  for (const r of d.reasons) console.log(`  ${r.severity} ${r.code}`);
  for (const r of d.evidence?.x509?.revocation ?? []) {
    console.log(`  certificate ${r.index}: ${r.status}${r.reason ? ` (${r.reason})` : ''}${r.source ? `, CRL from ${r.source}` : ''}`);
  }
};

const pinnedOnly = process.argv[2] === 'pinned';
const strict = process.argv[3] === 'strict';
const trust = createTrustClient(pinnedOnly
  ? {
    pinned: { anchors: [{ domain: 'mdoc-iaca', certificate: pem('iaca'), constraints: { docTypes: [mdl.credentialType] } }] },
    // The app's own minimum: in force with or without a snapshot, whatever the client profile says.
    ...(strict ? { policy: { requireRevocationStatus: true } } : {}),
  }
  : {
    // trustOnFirstUse and insecureHosts are for a service on localhost; an app ships keys: { thumbprints: [...] }.
    service: { url: 'http://localhost:8095', clientId: 'wallet', apiKey: 'wallet-key', keys: { trustOnFirstUse: true } },
    http: { insecureHosts: ['localhost'] },
  });

if (!pinnedOnly) {
  const snapshot = await trust.sync();
  console.log(`snapshot: ${snapshot.anchors} anchors, ${snapshot.entities} entities, ${snapshot.crls} CRLs, ${snapshot.didDocuments} DID documents, `
    + `${snapshot.mechanisms} trust mechanism${snapshot.mechanisms === 1 ? '' : 's'}`);
}
const { rules } = await trust.status();
const mechanisms = rules.mechanisms.map((m) => m.id);
console.log(`rules in force: ${Object.keys(rules).filter((r) => rules[r] === true).join(', ') || 'none'}`
  + (mechanisms.length ? `; trust mechanisms: ${mechanisms.join(', ')}` : ''));

// X.509 chains: an mdoc Document Signer under the IACA, one that was revoked, and one under nobody's IACA.
show('Document Signer', await trust.evaluate({ role: 'issuer', subject: { x5c: [x5c('ds')] }, context: mdl }));
show('revoked Document Signer', await trust.evaluate({ role: 'issuer', subject: { x5c: [x5c('ds-revoked')] }, context: mdl }));
show('Document Signer of an unlisted IACA', await trust.evaluate({ role: 'issuer', subject: { x5c: [x5c('rogue-ds')] }, context: mdl }));

if (!pinnedOnly) {
  // A chain with an intermediate CA, as an SD-JWT VC carries it in x5c: leaf first, the root left out.
  show('SD-JWT VC signer under an intermediate', await trust.evaluate({
    role: 'issuer', subject: { x5c: [x5c('chain-leaf'), x5c('chain-ca')] }, context: { credentialFormat: 'dc+sd-jwt' } }));

  // An OpenID4VP verifier that signs its request with a certificate and names itself by a DNS name in it.
  show('verifier', await trust.evaluateVerifier({
    clientId: 'x509_san_dns:verifier.example', x5c: [x5c('rp')], responseUri: 'https://verifier.example/response' }));

  // A DID: the key must be in the DID document and listed under assertionMethod.
  const did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  show('DID issuer', await trust.evaluateIssuer({
    did, kid: `${did}#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`, format: 'ldp_vc', type: 'UniversityDegreeCredential' }));

  // An identifier alone, as in a credential offer: a registry lookup.
  show('issuer URL', await trust.evaluateIssuer({ credentialIssuer: 'https://issuer.utopia.example' }));

  // The trust mechanism of application.yml: ID cards (org.example.id.*) count only the CA of the national-id domain,
  // under a certificate profile of their own, and need a known revocation status.
  const idCard = { credentialFormat: 'mso_mdoc', credentialType: 'org.example.id.card' };
  show('national ID signer', await trust.evaluate({ role: 'issuer', subject: { x5c: [x5c('nid-signer')] }, context: idCard }));
  show('national ID signer naming no CRL distribution point', await trust.evaluate({ role: 'issuer', subject: { x5c: [x5c('nid-no-dp')] }, context: idCard }));
  show('Document Signer of the IACA, for an ID card', await trust.evaluate({ role: 'issuer', subject: { x5c: [x5c('ds')] }, context: idCard }));
}
