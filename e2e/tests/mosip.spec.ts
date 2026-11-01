/**
 * OPT-IN (MOSIP=1): wallet-initiated authorization-code issuance from a MOSIP collab issuer in the web build, via the
 * dev CORS relay. The eSignet OTP login runs headless with tools/mosip-issuance (MOSIP's registered redirect is the
 * Inji app scheme, so the wallet gets the redirect URL pasted, exactly as a web user would).
 */
import { expect, test } from '@playwright/test';
// @ts-expect-error untyped helper script
import { loginAndGetCode } from '../../tools/mosip-issuance/issue.mjs';

const REDIRECT = 'io.mosip.residentapp.inji://oauthredirect';

test.skip(!process.env.MOSIP, 'set MOSIP=1 to run against MOSIP collab (slow, needs network)');

test('MOSIP Farmer credential (ldp_vc) via authorization code + pasted redirect', async ({ page }) => {
  test.setTimeout(300_000);
  await page.goto('/');
  await page.getByTestId('nav-receive').click();
  await page.getByTestId('tab-issuers').click();
  await page.getByTestId('issuer-pick-mosip-farmer').click();
  await expect(page.getByTestId('picked-trust-decision')).toHaveText('TRUSTED', { timeout: 60_000 });
  await page.getByTestId('issuer-start').click();
  await expect(page.getByTestId('offer-grant')).toHaveText('authorization_code', { timeout: 60_000 });
  await expect(page.getByTestId('issuer-trust-decision')).toHaveText('TRUSTED');

  const popupPromise = page.waitForEvent('popup');
  await page.getByTestId('auth-begin').click();
  await (await popupPromise).close();
  const authorizationUrl = await page.getByTestId('auth-url').innerText();
  const { redirectUrl } = await loginAndGetCode(authorizationUrl, REDIRECT, { log: () => undefined });

  await page.getByTestId('auth-callback-input').fill(redirectUrl);
  await page.getByTestId('auth-complete').click();
  await expect(page.getByTestId('issued-trust-0-decision')).toHaveText('TRUSTED', { timeout: 120_000 });
  await expect(page.getByTestId('issued-trust-0-valid')).toHaveText('✓ valid signature');
  await page.getByTestId('receive-done').click();
  await page.getByTestId('credential-card-0').click();
  await expect(page.getByTestId('evidence-did')).toBeVisible();
  const shot = test.info().outputPath('mosip-farmer.png');
  await page.screenshot({ path: shot, fullPage: true });
  await test.info().attach('mosip-farmer', { path: shot, contentType: 'image/png' });
});
