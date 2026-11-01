/**
 * Android Credential Manager bridge for the Digital Credentials API (W3C DC API / OpenID4VP Appendix A).
 *
 * The wallet registers what it holds (format, type, claim paths and display names); the platform's OpenID4VP matcher
 * decides which requests the wallet can answer and shows it in the system picker. When the user picks it, Android starts
 * this module's activity, which renders the "dcapi" React component with the request and the verifier's origin.
 * Absent (web, Expo Go, iOS) the functions are no-ops and {@link dcApiAvailable} is false.
 */
import { requireOptionalNativeModule } from 'expo';

/** One credential as the platform matcher sees it. Claim values are kept on the device by the registry. */
export interface DcApiEntry {
  id: string;
  format: 'mso_mdoc' | 'dc+sd-jwt';
  /** mso_mdoc doctype or SD-JWT VC vct */
  type: string;
  title: string;
  subtitle: string;
  claims: { path: string[]; name: string; value?: string }[];
}

/** What the activity hands to the "dcapi" component. */
export interface DcApiLaunch {
  /** the GetDigitalCredentialOption request JSON: {requests: [{protocol, data}]} */
  requestJson?: string;
  /** the verifier origin, from Chrome (allow-listed browser) or android:apk-key-hash:<hash> for an app */
  origin?: string;
  /** what the user picked in the system picker: {requestIndex?, credentials: {dcqlCredentialId: credentialId}, entryId?} */
  selectionJson?: string;
  /** set when the activity could not read the request, or refused who started it */
  error?: string;
  /** this launch's id: an answer completes only the request it was built for */
  token?: string;
}

interface DcApiNative {
  registerCredentials(entriesJson: string): Promise<number>;
  finish(token: string, responseJson: string): boolean;
  cancel(token: string): boolean;
}

const native = requireOptionalNativeModule<DcApiNative>('DcApi');

export const dcApiAvailable = !!native;

/** Replaces what the wallet offers to DC API requests; returns how many entries were registered. */
export async function registerCredentials(entries: DcApiEntry[]): Promise<number> {
  return native ? native.registerCredentials(JSON.stringify(entries)) : 0;
}

/**
 * Returns the response ({protocol, data}) to the verifier of the request launched with {@code token} and closes the
 * wallet's activity. False when that request is no longer open.
 */
export function finish(token: string, protocol: string, data: Record<string, unknown>): boolean {
  return native?.finish(token, JSON.stringify({ protocol, data })) ?? false;
}

/**
 * Ends the request without a response. The platform shows its picker again; when the user closes it, the verifier sees
 * the same error as for any other abort (OpenID4VP §15.9.2).
 */
export function cancel(token: string): boolean {
  return native?.cancel(token) ?? false;
}
