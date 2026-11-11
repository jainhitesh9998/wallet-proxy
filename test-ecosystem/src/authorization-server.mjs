/**
 * The issuer's OAuth 2.0 authorization server on @openid4vc/oauth2: the pre-authorized code grant (OpenID4VCI 1.0
 * sections 6.1 to 6.3), the authorization code grant (RFC 6749 section 4.1) with PKCE S256 (RFC 7636) and pushed
 * authorization requests (RFC 9126), DPoP-bound access tokens when the client sends a proof (RFC 9449), and JWT access
 * tokens (RFC 9068). A test server: `/authorize` asks nobody and redirects straight back with a code, any client_id
 * and redirect_uri are accepted, and its state lives in memory.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { authorizationCodeGrantIdentifier, Oauth2AuthorizationServer, Oauth2ResourceServer, Oauth2ResourceUnauthorizedError, Oauth2ServerErrorResponseError,
  parsePushedAuthorizationRequestUriReferenceValue, PkceCodeChallengeMethod, preAuthorizedCodeGrantIdentifier, pushedAuthorizationRequestUriPrefix } from '@openid4vc/oauth2';
import { publicOf } from './keys.mjs';

const REQUEST_URI_TTL_S = 60;
const CODE_TTL_S = 60;
const TOKEN_TTL_S = 600;
const DPOP_MAX_AGE_S = 300;
const SIGNING_ALGORITHMS = ['ES256'];

export const oauthError = (error, description, status) => new Oauth2ServerErrorResponseError({ error, error_description: description }, status ? { status } : undefined);
const secret = () => randomBytes(24).toString('base64url');
const isUrl = (value) => typeof value === 'string' && URL.canParse(value);

/**
 * @param {{ baseUrl: string, callbacks: object, tokenKey: JsonWebKey, configurations: Record<string, { scope: string }>,
 *   offers: Map<string, object> }} opts `offers` is the issuer's table of credential offers (see issuer.mjs)
 */
export function createAuthorizationServer({ baseUrl, callbacks, tokenKey, configurations, offers }) {
  const server = new Oauth2AuthorizationServer({ callbacks });
  const jwks = { keys: [publicOf(tokenKey)] };
  const resourceServer = new Oauth2ResourceServer({ callbacks: { ...callbacks, getJwks: () => jwks } });
  const metadata = server.createAuthorizationServerMetadata({
    issuer: baseUrl, authorization_endpoint: `${baseUrl}/authorize`, pushed_authorization_request_endpoint: `${baseUrl}/par`,
    token_endpoint: `${baseUrl}/token`, jwks_uri: `${baseUrl}/jwks`,
    grant_types_supported: [authorizationCodeGrantIdentifier, preAuthorizedCodeGrantIdentifier], response_types_supported: ['code'],
    code_challenge_methods_supported: [PkceCodeChallengeMethod.S256], token_endpoint_auth_methods_supported: ['none'],
    scopes_supported: [...new Set(Object.values(configurations).map((c) => c.scope))],
    'pre-authorized_grant_anonymous_access_supported': true, authorization_response_iss_parameter_supported: true,
    dpop_signing_alg_values_supported: SIGNING_ALGORITHMS,
  });

  /** request_uri reference → pushed authorization; code → authorization; grant id → what an access token may obtain */
  const pushed = new Map();
  const codes = new Map();
  const grants = new Map();
  const dpopProofs = new Set();
  // RFC 9449 section 11.1: a proof is good once. Proofs older than the accepted age are refused before this is asked.
  const dpop = { allowedSigningAlgs: SIGNING_ALGORITHMS, maxProofAgeSeconds: DPOP_MAX_AGE_S, allowedSkewInSeconds: 30,
    assertJtiUniqueness: ({ payload, jwkThumbprint }) => { const id = `${jwkThumbprint} ${payload.jti}`; return !dpopProofs.has(id) && Boolean(dpopProofs.add(id)); } };

  const usableOffer = (member, value) => [...offers.values()].find((o) => o[member] === value && !o.redeemed && o.expiresAt > Date.now());

  /** RFC 9396 authorization details of type openid_credential (OpenID4VCI 1.0 section 5.1.1), or undefined when absent. */
  function credentialDetails(value) {
    if (value === undefined) return undefined;
    let details;
    try { details = typeof value === 'string' ? JSON.parse(value) : value; } catch { details = undefined; }
    if (!Array.isArray(details) || details.length === 0 || details.some((d) => d?.type !== 'openid_credential' || typeof d.credential_configuration_id !== 'string')) {
      throw oauthError('invalid_authorization_details', 'authorization_details must be openid_credential objects with a credential_configuration_id');
    }
    return details;
  }

  /**
   * What an authorization covers. With an offer it is the offer's configurations; a wallet-initiated request names them
   * by scope. Authorization details narrow either, and make the token response carry credential identifiers (6.2).
   */
  function createGrant({ offer, scope, authorizationDetails, clientId }) {
    const details = credentialDetails(authorizationDetails);
    const scopes = (scope ?? '').split(' ');
    const allowed = offer ? offer.configurationIds : Object.keys(configurations);
    const configurationIds = details ? details.map((d) => d.credential_configuration_id) : offer ? allowed : allowed.filter((id) => scopes.includes(configurations[id].scope));
    if (configurationIds.some((id) => !allowed.includes(id))) throw oauthError('invalid_authorization_details', 'authorization_details name a credential configuration that is not on offer');
    if (configurationIds.length === 0) throw oauthError('invalid_scope', 'The request names no credential: use the scope of a credential configuration, or authorization_details');
    return { id: randomUUID(), offerId: offer?.id, clientId, configurationIds,
      identifiers: details ? Object.fromEntries(configurationIds.map((id) => [`${id}:${secret()}`, id])) : undefined };
  }

  /** Validates the parameters of an authorization request, pushed or not. */
  function authorizationOf(params, dpopJkt) {
    if (params.response_type !== 'code') throw oauthError('unsupported_response_type', 'Only response_type=code is supported');
    if (!params.code_challenge || params.code_challenge_method !== PkceCodeChallengeMethod.S256) throw oauthError('invalid_request', 'PKCE with code_challenge_method=S256 is required');
    const offer = params.issuer_state === undefined ? undefined : usableOffer('issuerState', params.issuer_state);
    if (params.issuer_state !== undefined && !offer) throw oauthError('invalid_request', 'Unknown, used or expired issuer_state');
    return { clientId: params.client_id, redirectUri: params.redirect_uri, state: params.state, codeChallenge: params.code_challenge, dpopJkt,
      grant: createGrant({ offer, scope: params.scope, authorizationDetails: params.authorization_details, clientId: params.client_id }) };
  }

  /** RFC 9126 section 2. */
  async function par(request, body) {
    const parsed = await server.parsePushedAuthorizationRequest({ request, authorizationRequest: body });
    if (parsed.authorizationRequestJwt) throw oauthError('invalid_request', 'Signed request objects are not supported');
    if (!isUrl(parsed.authorizationRequest.redirect_uri)) throw oauthError('invalid_request', 'redirect_uri is required');
    const verified = await server.verifyPushedAuthorizationRequest({ authorizationRequest: parsed.authorizationRequest, authorizationServerMetadata: metadata, request,
      dpop: { ...dpop, jwt: parsed.dpop?.jwt, jwkThumbprint: parsed.dpop?.jwkThumbprint } });
    const reference = secret();
    pushed.set(reference, { ...authorizationOf(parsed.authorizationRequest, verified.dpop?.jwkThumbprint), expiresAt: Date.now() + REQUEST_URI_TTL_S * 1000 });
    return server.createPushedAuthorizationResponse({ requestUri: `${pushedAuthorizationRequestUriPrefix}${reference}`, expiresInSeconds: REQUEST_URI_TTL_S });
  }

  /**
   * The authorization endpoint (RFC 6749 section 4.1.1), without a user: the response is the redirect back to the
   * client with a code, or with the error when the request is refused (section 4.1.2.1). `iss` is RFC 9207.
   * @returns {{ status: number, headers: { Location: string } }}
   */
  function authorize(request) {
    const params = Object.fromEntries(new URL(request.url).searchParams);
    const redirect = (uri, query) => {
      const location = new URL(uri);
      for (const [name, value] of Object.entries({ ...query, iss: baseUrl })) if (value !== undefined) location.searchParams.set(name, value);
      return { status: 302, headers: { Location: location.toString(), 'Cache-Control': 'no-store' } };
    };
    let authorization;
    if (params.request_uri !== undefined) {
      const reference = parsePushedAuthorizationRequestUriReferenceValue({ uri: params.request_uri });
      authorization = pushed.get(reference);
      pushed.delete(reference);
      if (!authorization || authorization.expiresAt < Date.now() || authorization.clientId !== params.client_id) throw oauthError('invalid_request', 'Unknown, used or expired request_uri');
    } else {
      // Without a usable client_id and redirect_uri there is nowhere to send an error, so these two fail here.
      if (!params.client_id || !isUrl(params.redirect_uri)) throw oauthError('invalid_request', 'client_id and redirect_uri are required');
      try {
        authorization = authorizationOf(params, params.dpop_jkt);
      } catch (e) {
        if (!(e instanceof Oauth2ServerErrorResponseError)) throw e;
        return redirect(params.redirect_uri, { ...e.errorResponse, state: params.state });
      }
    }
    const code = secret();
    codes.set(code, { ...authorization, expiresAt: Date.now() + CODE_TTL_S * 1000 });
    return redirect(authorization.redirectUri, { code, state: authorization.state });
  }

  /** The token endpoint, for both grants. A code is spent by the first request that presents it, whatever the outcome. */
  async function token(request, body) {
    const parsed = server.parseAccessTokenRequest({ request, accessTokenRequest: body, authorizationServerMetadata: metadata });
    const common = { authorizationServerMetadata: metadata, grant: parsed.grant, accessTokenRequest: parsed.accessTokenRequest, request };
    let grant;
    let verified;
    if (parsed.grant.grantType === preAuthorizedCodeGrantIdentifier) {
      const offer = usableOffer('preAuthorizedCode', parsed.grant.preAuthorizedCode);
      if (!offer) throw oauthError('invalid_grant', 'Unknown, used or expired pre-authorized code');
      verified = await server.verifyPreAuthorizedCodeAccessTokenRequest({ ...common, expectedPreAuthorizedCode: offer.preAuthorizedCode, expectedTxCode: offer.txCode,
        preAuthorizedCodeExpiresAt: new Date(offer.expiresAt), dpop: { ...dpop, jwt: parsed.dpop?.jwt } });
      grant = createGrant({ offer, authorizationDetails: body.authorization_details, clientId: body.client_id });
    } else if (parsed.grant.grantType === authorizationCodeGrantIdentifier) {
      const authorization = codes.get(parsed.grant.code);
      codes.delete(parsed.grant.code);
      if (!authorization) throw oauthError('invalid_grant', 'Unknown or used authorization code');
      verified = await server.verifyAuthorizationCodeAccessTokenRequest({ ...common, expectedCode: parsed.grant.code, codeExpiresAt: new Date(authorization.expiresAt),
        pkce: { codeVerifier: parsed.pkceCodeVerifier, codeChallenge: authorization.codeChallenge, codeChallengeMethod: PkceCodeChallengeMethod.S256 },
        dpop: { ...dpop, jwt: parsed.dpop?.jwt, required: Boolean(authorization.dpopJkt), expectedJwkThumbprint: authorization.dpopJkt } });
      // RFC 6749 section 4.1.3: the client and the redirect_uri are those of the authorization request.
      if (body.client_id !== authorization.clientId || body.redirect_uri !== authorization.redirectUri) throw oauthError('invalid_grant', 'client_id or redirect_uri differ from the authorization request');
      grant = authorization.grant;
    } else {
      throw oauthError('unsupported_grant_type', `Grant type ${parsed.grant.grantType} is not supported`);
    }
    if (grant.offerId) offers.get(grant.offerId).redeemed = true;
    grants.set(grant.id, grant);
    return server.createAccessTokenResponse({
      audience: baseUrl, authorizationServer: baseUrl, subject: grant.id, clientId: grant.clientId, expiresInSeconds: TOKEN_TTL_S,
      signer: { method: 'jwk', publicJwk: publicOf(tokenKey), alg: 'ES256' }, dpop: verified.dpop ? { jwk: verified.dpop.jwk } : undefined,
      additionalAccessTokenResponsePayload: grant.identifiers && { authorization_details: Object.entries(grant.identifiers).map(([identifier, id]) => (
        { type: 'openid_credential', credential_configuration_id: id, credential_identifiers: [identifier] })) },
    });
  }

  /**
   * Authenticates a request to a protected endpoint (RFC 6750, and RFC 9449 section 7 for a DPoP-bound token).
   * @returns {Promise<{ id: string, offerId?: string, clientId?: string, configurationIds: string[], identifiers?: Record<string, string> }>}
   */
  async function authenticate(request) {
    const { tokenPayload, scheme } = await resourceServer.verifyResourceRequest({ request, resourceServer: baseUrl, authorizationServers: [metadata], dpop });
    const grant = grants.get(tokenPayload.sub);
    if (!grant) throw new Oauth2ResourceUnauthorizedError('The access token belongs to no grant', { scheme, error: 'invalid_token' });
    return grant;
  }

  return { metadata, jwks, par, authorize, token, authenticate };
}
