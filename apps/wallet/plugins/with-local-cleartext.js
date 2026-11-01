/**
 * Android release builds refuse plain http. The demo trust service and CORS relay run on the developer's machine over
 * http, so allow cleartext to the loopback / emulator host addresses only (reach them with `adb reverse`); every other
 * host stays https-only.
 */
const fs = require('fs');
const path = require('path');
const { withAndroidManifest, withDangerousMod } = require('expo/config-plugins');

const CONFIG = `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="false">localhost</domain>
    <domain includeSubdomains="false">127.0.0.1</domain>
    <domain includeSubdomains="false">10.0.2.2</domain>
  </domain-config>
</network-security-config>
`;

module.exports = function withLocalCleartext(config) {
  config = withDangerousMod(config, ['android', async (c) => {
    const dir = path.join(c.modRequest.platformProjectRoot, 'app/src/main/res/xml');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'network_security_config.xml'), CONFIG);
    return c;
  }]);
  return withAndroidManifest(config, (c) => {
    c.modResults.manifest.application[0].$['android:networkSecurityConfig'] = '@xml/network_security_config';
    return c;
  });
};
