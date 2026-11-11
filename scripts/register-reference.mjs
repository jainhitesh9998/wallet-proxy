#!/usr/bin/env node
/**
 * Lists the reference issuer and verifier (test-ecosystem/) in a running trust service, the way an operator would
 * list any party: who they are, which certificates are theirs, which JSON-LD contexts their credentials use.
 * Entries go through the admin API to the managed source of the 'reference' framework.
 *
 *   node scripts/register-reference.mjs            # register
 *   node scripts/register-reference.mjs --remove   # remove again
 *
 * TRUST_URL (http://localhost:8090), TRUST_ADMIN_KEY (admin-key), ISSUER_URL (http://localhost:8791) and
 * VERIFIER_URL (http://localhost:8792) come from the environment.
 */
const TRUST = process.env.TRUST_URL ?? 'http://localhost:8090';
const ADMIN_KEY = process.env.TRUST_ADMIN_KEY ?? 'admin-key';
const ISSUER = process.env.ISSUER_URL ?? 'http://localhost:8791';
const VERIFIER = process.env.VERIFIER_URL ?? 'http://localhost:8792';
const FRAMEWORK = 'reference';

async function managed(method, kind, id, body) {
  const r = await fetch(`${TRUST}/admin/v1/managed/${kind}/${id}`, { method, headers: { Authorization: `Bearer ${ADMIN_KEY}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body) });
  if (!r.ok && !(method === 'DELETE' && r.status === 404)) throw new Error(`${method} ${kind}/${id}: HTTP ${r.status} ${(await r.text()).slice(0, 300)}`);
  console.log(`${method === 'PUT' ? 'registered' : 'removed'} ${kind}/${id}`);
}
const text = async (url) => {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status} (is the reference ecosystem running? npm start -w @vctrust/reference-ecosystem)`);
  return r.text();
};

const entities = ['reference-issuer', 'reference-verifier'];
const anchors = ['reference-iaca', 'reference-issuer-ca', 'reference-verifier-ca'];

if (process.argv.includes('--remove')) {
  for (const id of anchors) await managed('DELETE', 'anchors', id);
  for (const id of entities) await managed('DELETE', 'entities', id);
} else {
  // The verifier's client identifier (x509_hash of its certificate) is in every request it creates.
  const request = await (await fetch(`${VERIFIER}/api/requests`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credentials: [{ format: 'mso_mdoc', doctype: 'org.iso.18013.5.1.mDL' }] }) })).json();
  const clientId = new URLSearchParams(String(request.authorizationRequestUri).split('?')[1]).get('client_id');
  const did = `did:web:${encodeURIComponent(new URL(ISSUER).host)}`;

  await managed('PUT', 'entities', entities[0], { framework: FRAMEWORK, roles: ['CREDENTIAL_ISSUER'], name: 'Reference issuer',
    identifiers: [{ type: 'URL', value: ISSUER }, did], contexts: [`${ISSUER}/contexts/reference/v1`],
    authorizations: [{ format: 'mso_mdoc', type: 'org.iso.18013.5.1.mDL' }, { format: 'dc+sd-jwt', type: 'urn:reference:identity:1' },
      { format: 'ldp_vc', type: 'UniversityDegreeCredential' }] });
  await managed('PUT', 'entities', entities[1], { framework: FRAMEWORK, roles: ['VERIFIER'], name: 'Reference verifier', identifiers: [{ type: 'CLIENT_ID', value: clientId }] });
  await managed('PUT', 'anchors', anchors[0], { framework: FRAMEWORK, domain: 'mdoc-iaca', entity: entities[0], certificate: await text(`${ISSUER}/pki/iaca.pem`),
    constraints: { docTypes: ['org.iso.18013.5.1.mDL'], crlUrls: [`${ISSUER}/pki/iaca.crl`] } });
  await managed('PUT', 'anchors', anchors[1], { framework: FRAMEWORK, domain: 'credential-issuer', entity: entities[0], certificate: await text(`${ISSUER}/pki/issuer-ca.pem`) });
  await managed('PUT', 'anchors', anchors[2], { framework: FRAMEWORK, domain: 'verifier-access', certificate: await text(`${VERIFIER}/pki/verifier-ca.pem`) });
  console.log(`\nThe demo clients (frameworks animo-playground, reference, local) now see the reference issuer ${ISSUER} (${did}) and verifier ${clientId}.`);
}
