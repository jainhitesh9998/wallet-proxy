/**
 * The wallet of the tests: the protocol library's own clients (`Openid4vciClient`, `Openid4vpClient`), so that the
 * issuer and the verifier are exercised by code that was not written against them. It holds one key per credential.
 */
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { randomUUID } from 'node:crypto';
import { clientAuthenticationNone } from '@openid4vc/oauth2';
import { Openid4vciClient } from '@openid4vc/openid4vci';
import { Openid4vpClient } from '@openid4vc/openid4vp';
import { b64u, generateEcJwk, joseCallbacks, publicOf, RESPONSE_ENCRYPTION } from '../src/keys.mjs';

const REDIRECT_URI = 'http://localhost/wallet/callback';
const CLIENT_ID = 'reference-test-wallet';

/** The subject alternative names of a certificate, which the library asks for when it checks an X.509 client identifier. */
function getX509CertificateMetadata(certificate) {
  const names = new x509.X509Certificate(certificate).getExtension(x509.SubjectAlternativeNameExtension)?.names.items ?? [];
  return { sanDnsNames: names.filter((n) => n.type === 'dns').map((n) => n.value), sanUriNames: names.filter((n) => n.type === 'url').map((n) => n.value) };
}

export const didJwk = (key) => `did:jwk:${b64u(JSON.stringify(publicOf(key)))}`;

export function createWallet() {
  const keys = [];
  const callbacks = { ...joseCallbacks(keys), clientAuthentication: clientAuthenticationNone({ clientId: CLIENT_ID }), getX509CertificateMetadata };
  const client = new Openid4vciClient({ callbacks });
  const presenter = new Openid4vpClient({ callbacks });
  const newKey = async () => { const key = await generateEcJwk(); keys.push(key); return key; };
  const jwkSigner = (key) => ({ method: 'jwk', alg: 'ES256', publicJwk: publicOf(key) });
  /** The form of the key the credential format binds to: a did:jwk for ldp_vc, the key itself otherwise. */
  const proofSigner = (key, format) => (format === 'ldp_vc' ? { method: 'did', alg: 'ES256', didUrl: `${didJwk(key)}#0` } : jwkSigner(key));

  /** `count` jwt key proofs over a fresh nonce, each for a new key. */
  async function createProofs({ issuerMetadata, configurationId, count = 1 }) {
    const { c_nonce: nonce } = await client.requestNonce({ issuerMetadata });
    const format = issuerMetadata.credentialIssuer.credential_configurations_supported[configurationId].format;
    const holderKeys = [];
    const proofs = [];
    for (let i = 0; i < count; i++) {
      holderKeys.push(await newKey());
      const { jwt } = await client.createCredentialRequestJwtProof({ issuerMetadata, credentialConfigurationId: configurationId, signer: proofSigner(holderKeys[i], format), nonce, issuedAt: new Date() });
      proofs.push(jwt);
    }
    return { proofs, holderKeys };
  }

  /**
   * One credential request with `count` key proofs.
   * @returns {Promise<{ response: import('@openid4vc/openid4vci').CredentialResponse, holderKeys: object[] }>}
   */
  async function requestCredentials({ issuerMetadata, configurationId, token, count = 1 }) {
    const { proofs, holderKeys } = await createProofs({ issuerMetadata, configurationId, count });
    const { credentialResponse } = await client.retrieveCredentials({ issuerMetadata, accessToken: token.accessTokenResponse.access_token, dpop: token.dpop,
      credentialConfigurationId: configurationId, proofs: { jwt: proofs } });
    return { response: credentialResponse, holderKeys };
  }

  /** Resolves an offer URI and the issuer's metadata. */
  async function resolve(credentialOfferUri) {
    const credentialOffer = await client.resolveCredentialOffer(credentialOfferUri);
    return { credentialOffer, issuerMetadata: await client.resolveIssuerMetadata(credentialOffer.credential_issuer) };
  }

  /** Pre-authorized code flow (OpenID4VCI 1.0 section 6.1); with `dpop`, the token is bound to a new DPoP key. */
  async function preAuthorizedToken({ credentialOffer, issuerMetadata }, { txCode, dpop = false } = {}) {
    return client.retrievePreAuthorizedCodeAccessTokenFromOffer({ credentialOffer, issuerMetadata, txCode, dpop: dpop ? { signer: jwkSigner(await newKey()) } : undefined });
  }

  /**
   * Authorization code flow with PKCE, through PAR when the server offers it: follows the issuer's redirect for the
   * code. With `dpop`, the pushed request carries a DPoP proof, which binds the code to that key (RFC 9449 section 10).
   */
  async function authorizationCodeToken({ credentialOffer, issuerMetadata }, { dpop: withDpop = false } = {}) {
    const scope = [...new Set(credentialOffer.credential_configuration_ids.map((id) => issuerMetadata.credentialIssuer.credential_configurations_supported[id].scope))].join(' ');
    const { authorizationRequestUrl, pkce, dpop } = await client.createAuthorizationRequestUrlFromOffer({ clientId: CLIENT_ID, credentialOffer, issuerMetadata, redirectUri: REDIRECT_URI, scope,
      dpop: withDpop ? { signer: jwkSigner(await newKey()) } : undefined });
    const redirectUrl = (await fetch(authorizationRequestUrl, { redirect: 'manual' })).headers.get('location');
    const { code } = client.parseAndVerifyAuthorizationResponseRedirectUrl({ url: redirectUrl, authorizationServerMetadata: issuerMetadata.authorizationServers[0] });
    const exchange = { issuerMetadata, credentialOffer, authorizationCode: code, pkceCodeVerifier: pkce?.codeVerifier, redirectUri: REDIRECT_URI };
    return { authorizationRequestUrl, redirectUrl, exchange, redeem: (proof = dpop) => client.retrieveAuthorizationCodeAccessTokenFromOffer({ ...exchange, dpop: proof }) };
  }

  /** The whole pre-authorized flow for one credential: `{ credential, holderKey }`. */
  async function receive(credentialOfferUri, configurationId) {
    const session = await resolve(credentialOfferUri);
    const { response, holderKeys } = await requestCredentials({ ...session, configurationId, token: await preAuthorizedToken(session) });
    return { credential: response.credentials[0].credential, holderKey: holderKeys[0] };
  }

  /**
   * Answers an OpenID4VP request: fetches and verifies the request object, builds the vp_token with `makeVpToken`
   * (given the request parameters), and posts the response the way the request's response_mode says.
   * @param {string} authorizationRequestUri
   * @param {(request: Record<string, any>) => Promise<Record<string, unknown[]>>} makeVpToken
   * @returns {Promise<{ request: Record<string, any>, signer: object, status: number, body: any }>}
   */
  async function present(authorizationRequestUri, makeVpToken) {
    const parsed = presenter.parseOpenid4vpAuthorizationRequest({ authorizationRequest: authorizationRequestUri });
    const { authorizationRequestPayload: request, jar } = await presenter.resolveOpenId4vpAuthorizationRequest({ authorizationRequestPayload: parsed.params, responseMode: { type: 'direct_post' } });
    const { authorizationResponsePayload, jarm } = await presenter.createOpenid4vpAuthorizationResponse({
      authorizationRequestPayload: request, authorizationResponsePayload: { vp_token: await makeVpToken(request) },
      jarm: request.response_mode === 'direct_post.jwt' ? { encryption: { nonce: randomUUID() },
        serverMetadata: { authorization_encryption_alg_values_supported: [RESPONSE_ENCRYPTION.alg], authorization_encryption_enc_values_supported: RESPONSE_ENCRYPTION.enc } } : undefined,
    });
    const { response } = await presenter.submitOpenid4vpAuthorizationResponse({ authorizationRequestPayload: request, authorizationResponsePayload, jarm: jarm && { responseJwt: jarm.responseJwt } });
    return { request, signer: jar.signer, status: response.status, body: await response.json() };
  }

  return { client, resolve, preAuthorizedToken, authorizationCodeToken, createProofs, requestCredentials, receive, present };
}
